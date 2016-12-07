#!/usr/bin/python3

import sys
import sqlite3
import re
import netaddr
import utils
from utils import *

def IP2BLOB(ip):
	ip = int(IP(ip).ipv6())
	return sqlite3.Binary( ip.to_bytes(128,byteorder='big') )
	
def BLOB2IP(blob):
	return IP(int.from_bytes(blob,byteorder='big'))

def ipaddr2sqlite(ip):
	ip = int(ip.ipv6())
	return sqlite3.Binary( ip.to_bytes(128,byteorder='big') )

sqlite3.register_adapter(netaddr.IPAddress,ipaddr2sqlite)

sqlite3.register_converter("blobip", BLOB2IP)

conn = sqlite3.connect(__name__ == "__main__" and ":memory:" or 'state.db',detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)

def commit():
	conn.commit()

conn.executescript('''


CREATE TABLE IF NOT EXISTS "ips" (
	`ip`			blobip NOT NULL UNIQUE,
	`networkid`		INTEGER,
	`lookuptype`	INTEGER,
	`failurereason`	TEXT,
	PRIMARY KEY(`ip`)
);

CREATE TABLE IF NOT EXISTS "networks" (
	`networkid`		INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	`startip`		blobip NOT NULL,
	`endip`			blobip NOT NULL,
	`origin_ip`	blobip NOT NULL,
	UNIQUE(`startip`,`endip`)
);

CREATE TABLE IF NOT EXISTS "abuse_emails" (
	`networkid`	INTEGER NOT NULL,
	`e1`	TEXT,
	`e2`	TEXT,
	`e3`	TEXT,
	`e1_quality`	INTEGER,
	`e2_quality`	INTEGER,
	`e3_quality`	INTEGER,
	PRIMARY KEY(`networkid`),
	FOREIGN KEY(`networkid`) REFERENCES networks
);

''')

conn.commit()
cur = conn.cursor()


def network_from_ip(ip):
	ip = IP(ip)
	
	q = conn.execute("""SELECT networkid,startip,endip FROM networks WHERE ? >= startip AND ? <= endip ORDER BY startip""",(ip,ip,))
	
	#TODO: Find better way
	smallest=q.fetchone()
	i=0
	for network in q:
		i=i+1
		(snetworkid,sstartip,sendip,) = smallest
		(networkid,startip,endip,) = network
		if abs(int(endip)-int(startip))<abs(int(sendip)-int(sstartip)):
			smallest = network
	assert(i<10)
	if smallest:
		(networkid,*a) = smallest
		return networkid

def addips(ips):
	
	iplist=[]
	for ip in ips:
		iplist.append( (IP(ip), ) )
	
	cur.executemany("INSERT OR IGNORE INTO ips('ip') values (?)",iplist)
	conn.commit()
	return (cur.rowcount,len(iplist))

def get_network(startip,endip,origin_ip=None):
	startip = IP(startip)
	endip = IP(endip)
	if origin_ip:
		origin_ip = IP(origin_ip)
		
	networkid = network_from_ip(startip) or (startip!=endip and network_from_ip(endip))
	if networkid:
		return networkid

	cur.execute("INSERT INTO networks('startip','endip','origin_ip') values (?,?,?)", (startip,endip,origin_ip, ) )
	conn.commit()
	networkid = cur.lastrowid
	#print(network_from_ip(startip),networkid)
	assert(networkid==network_from_ip(startip))
	
	return networkid
	
def add_network_abusemails(networkid,abuseemails,quality=None):
	
	assert(networkid>0)
	
	#TODO: Normalize...
	
	e1         = len(abuseemails)>0 and abuseemails[0]
	e2         = len(abuseemails)>1 and abuseemails[1]
	e3         = len(abuseemails)>2 and abuseemails[2]
	
	cur.execute("INSERT OR IGNORE INTO abuse_emails(networkid,e1,e2,e3,e1_quality,e2_quality,e3_quality) values (?,?,?,?,?,?,?)",
		(
			networkid,
			e1 or None,
			e2 or None,
			e3 or None,
			quality and e1 and quality[0] or None,
			quality and e2 and quality[1] or None,
			quality and e3 and quality[2] or None
		)
	)
	conn.commit()
	

# False == Failure == -1
def ip_set_network(ips,networkid=-1,failurereason=None):
	
	ips = type(ips) is list and ips or [ips]
	
	updatelist=[]
	for ip in ips:
		updatelist.append((	networkid or -1,
							failurereason,
							IP(ip),  			))
			
	cur.executemany("UPDATE ips SET networkid=?,failurereason=? WHERE ip=? AND (networkid IS NULL or networkid=-1)",updatelist)
	conn.commit()
	return ( cur.rowcount,len(updatelist) )

def get_unprocessed(random_order=False):
	if random_order:
		return conn.execute("""SELECT ip FROM ips WHERE networkid IS NULL ORDER BY RANDOM()""")
		
	return conn.execute("""SELECT ip FROM ips WHERE networkid IS NULL""")

def network_has_mails_processed(networkid):
	res = conn.execute("""SELECT e1 FROM abuse_emails WHERE networkid = ? LIMIT 1""",(networkid,))
	if not res:
		return False
	res = res.fetchone()
	if not res:
		return False
	(e1,) = res
	if e1 is None:
		return False
	
def clear_failed_ips():
	return conn.execute("""UPDATE ips SET networkid=NULL,failurereason=NULL WHERE networkid=-1""")


def dump_all():
	return cur.execute("""
		SELECT ips.ip as ip, abuse_emails.e1 as e1, abuse_emails.e2 as e2, abuse_emails.e3 as e3 
		FROM ips 
			LEFT JOIN networks 
				ON ips.networkid=networks.networkid
			LEFT JOIN abuse_emails
				ON networks.networkid=abuse_emails.networkid
	""")

if __name__ == "__main__":
	print(addips(extract_ips("""
has address 88.114.107.102
IPv6 address 2001:470:27:1aa::2
""")))
	printp(dump_all.fetchall())