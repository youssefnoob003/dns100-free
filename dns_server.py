import socket
import socketserver
import threading
import time
import sqlite3
from dnslib import DNSRecord, RR, QTYPE, A, AAAA, CNAME, MX, NS, TXT, SRV, SOA, RCODE
from dnslib.dns import DNSHeader
import random
import base64
import subprocess
import tempfile
import os


def parse_dns_query(data):
    """Extract QNAME labels from a raw DNS query packet."""
    qname = []
    idx = 12
    length = data[idx]
    while length != 0:
        idx += 1
        qname.append(data[idx:idx+length].decode())
        idx += length
        length = data[idx]
    return qname


def ensure_db(db_path):
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    with conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS zones(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            ttl INTEGER,
            primary_ns TEXT,
            admin_email TEXT,
            serial INTEGER,
            refresh INTEGER,
            retry INTEGER,
            expire INTEGER,
            minimum INTEGER
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS records(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            zone_id INTEGER,
            name TEXT,
            type TEXT,
            content TEXT,
            ttl INTEGER DEFAULT 0,
            priority INTEGER
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS settings(
            key TEXT PRIMARY KEY,
            value TEXT
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts DATETIME DEFAULT CURRENT_TIMESTAMP,
            client_ip TEXT,
            qname TEXT,
            qtype TEXT,
            rcode TEXT,
            answer TEXT,
            duration_ms INTEGER
        )""")
        conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('listen_addr','0.0.0.0')")
        conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('listen_port','5353')")
        conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('default_ttl','300')")
        conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('upstream','')")
    return conn

def bump_zone_serial(conn, zone_id):
    conn.execute("UPDATE zones SET serial=serial+1 WHERE id=?", (zone_id,))

def fetch_settings(conn):
    cur = conn.execute("SELECT key,value FROM settings")
    return {k:v for k,v in cur.fetchall()}

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        client_ip = self.client_address[0]
        start = time.time()
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname)
            qtype = QTYPE[request.q.qtype]
            reply = self.server.answer_query(request)
            sock.sendto(reply.pack(), self.client_address)
            rcode = RCODE[reply.header.rcode]
            answers = ";".join([str(r.rdata) for r in reply.rr])
        except Exception as e:
            rcode = "SERVFAIL"
            answers = str(e)
        finally:
            dur = int((time.time()-start)*1000)
            with self.server.conn:
                self.server.conn.execute(
                    "INSERT INTO logs(client_ip,qname,qtype,rcode,answer,duration_ms) VALUES(?,?,?,?,?,?)",
                    (client_ip, locals().get('qname','?'), locals().get('qtype','?'), rcode, answers, dur)
                )



def send_test_dns_query(server_ip: str, keyword: str):
    """Send a test DNS query to a selected DNS server."""
    qname = f"{keyword}.example.local"
    query = DNSRecord.question(qname, qtype="A")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(query.pack(), (server_ip, 53))
        
    except Exception as e:
        sock.close()



