#!/usr/bin/python3

import sys
import sqlite3
import re
import netaddr
			
conn = sqlite3.connect('state.db',detect_types=sqlite3.PARSE_DECLTYPES)
def commit():
	conn.commit()

conn.executescript('''

CREATE TABLE IF NOT EXISTS "networks" (
	`networkid`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	`startip`	INTEGER NOT NULL CHECK(startip<=endip) UNIQUE,
	`endip`	INTEGER NOT NULL CHECK(endip>=startip) UNIQUE
);

CREATE TABLE IF NOT EXISTS "ips" (
	`ip`	INTEGER NOT NULL UNIQUE,
	`networkid`	INTEGER,
	PRIMARY KEY(`ip`)
);
CREATE TABLE IF NOT EXISTS "abuse_emails" (
	`networkid`	INTEGER NOT NULL,
	`e1`	TEXT,
	`e2`	TEXT,
	`e3`	TEXT,
	PRIMARY KEY(`networkid`), -- this makes no sense, but it's too late to turn back now
	FOREIGN KEY(`networkid`) REFERENCES networks
);

''')
conn.commit()

cur = conn.cursor()

def network_from_ip(ip):
	ip = int( netaddr.IPAddress(ip) )
	query = conn.execute("""SELECT networkid FROM networks WHERE startip <= ? AND endip >= ? LIMIT 2""",(ip,ip,))
	
	r = query.fetchone()
	if not r:
		return
	
	assert(not query.fetchone())
	
	return r['networkid']

def addips(ips):
	
	iplist=[]
	for ip in ips:
		tupl = (int(netaddr.IPAddress(ip)), )
		iplist.append( tupl )
	
	cur.executemany("INSERT OR IGNORE INTO ips('ip') values (?)",iplist)
	conn.commit()
	return (cur.rowcount,len(iplist))


def ip_setfail(ips):
	
	ips = type(ips) is list and ips or [ips]
	
	iplist=[]
	for ip in ips:
		tupl = (int(netaddr.IPAddress(ip)), )
		iplist.append( tupl )
	
	cur.executemany("UPDATE ips SET networkid=-1 WHERE ip=? AND networkid IS NULL",iplist)
	conn.commit()
	return (cur.rowcount,len(iplist))

def get_unprocessed():
	return conn.execute("""SELECT ip FROM ips WHERE networkid IS NULL""")



def dump_all():
	return cur.execute("""
		SELECT ips.ip as ip, abuse_emails.e1 as e1, abuse_emails.e2 as e2, abuse_emails.e3 as e3 
		FROM ips 
			LEFT JOIN networks 
				ON ips.networkid=networks.networkid
			LEFT JOIN abuse_emails
				ON networks.networkid=abuse_emails.networkid
	""")
