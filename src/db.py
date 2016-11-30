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
	`failurereason`	TEXT,
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
	q = conn.execute("""SELECT networkid,startip,endip FROM networks WHERE ? >= startip AND ? <= endip ORDER BY startip""",(ip,ip,))
	
	#TODO: Find better way
	smallest=q.fetchone()
	i=0
	for network in q:
		i=i+1
		(snetworkid,sstartip,sendip,) = smallest
		(networkid,startip,endip,) = network
		if abs(endip-startip)<abs(sendip-sstartip):
			smallest = network
	assert(i<10)
	if smallest:
		(networkid,*a) = smallest
		return networkid

def addips(ips):
	
	iplist=[]
	for ip in ips:
		tupl = (int(netaddr.IPAddress(ip)), )
		iplist.append( tupl )
	
	cur.executemany("INSERT OR IGNORE INTO ips('ip') values (?)",iplist)
	conn.commit()
	return (cur.rowcount,len(iplist))

def get_network(startip,endip):
	networkid = network_from_ip(startip) or (startip!=endip and network_from_ip(endip))
	if networkid:
		return networkid

	cur.execute("INSERT INTO networks('startip','endip') values (?,?)", (int(startip),int(endip), ) )
	conn.commit()
	networkid = cur.lastrowid
	#print(network_from_ip(startip),networkid)
	assert(networkid==network_from_ip(startip))
	
	return networkid
	
def add_network_abusemails(networkid,abuseemails):
	
	assert(networkid>0)
	
	l = len(abuseemails)
	cur.execute("INSERT OR IGNORE INTO abuse_emails(networkid,e1,e2,e3) values (?,?,?,?)",
		(
			networkid,
			l>0 and abuseemails[0] or None,
			l>1 and abuseemails[1] or None,
			l>2 and abuseemails[2] or None,
		)
	)
	conn.commit()
	

# False == Failure == -1
def ip_set_network(ips,networkid=-1):
	
	ips = type(ips) is list and ips or [ips]
	
	updatelist=[]
	for ip in ips:
		updatelist.append( ( 
			networkid or -1,
			int(netaddr.IPAddress(ip))   ) )
	cur.executemany("UPDATE ips SET networkid=? WHERE ip=? AND (networkid IS NULL or networkid=-1)",updatelist)
	conn.commit()
	return ( cur.rowcount,len(updatelist) )

def get_unprocessed(random_order=False):
	if random_order:
		return conn.execute("""SELECT ip FROM ips WHERE networkid IS NULL ORDER BY RANDOM()""")
		
	return conn.execute("""SELECT ip FROM ips WHERE networkid IS NULL""")

def clear_failed_ips():
	return conn.execute("""UPDATE ips SET networkid=NULL WHERE networkid=-1""")


def dump_all():
	return cur.execute("""
		SELECT ips.ip as ip, abuse_emails.e1 as e1, abuse_emails.e2 as e2, abuse_emails.e3 as e3 
		FROM ips 
			LEFT JOIN networks 
				ON ips.networkid=networks.networkid
			LEFT JOIN abuse_emails
				ON networks.networkid=abuse_emails.networkid
	""")
