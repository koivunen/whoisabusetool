import threading
import queue
from queue import Queue
import time
import ipwhois
from ipwhois import IPWhois
import netaddr
import pprint
import urllib
from utils import *
import urllib.request

#def genproxy(url,)
#	proxy_handler = urllib2.ProxyHandler({'http': 'http://45.62.228.192:8889'})
#	proxy_auth_handler = urllib2.HTTPBasicAuthHandler()
#	proxy_auth_handler.add_password('realm', 'host', 'username', 'password')
#	opener = urllib2.build_opener(proxy_handler, proxy_auth_handler)

import config
from config import proxies
config.test_proxies()

thread_to_id = {}

SIZE = len(proxies)

# Synchronized map?
next_query=[]
for i in range(SIZE):
	next_query.append({})

queries_remaining=0
q = Queue(maxsize=SIZE*2+1)
responses = Queue(maxsize=SIZE *2+1)
printlock = threading.Lock()

def dprint(*args, **kwargs):
	with printlock:
		print(*args, **kwargs)


def whoiser(item,proxyid):

	ip = IP(item['ip'])
	if ip.is_ipv4_mapped():
		ip = ip.ipv4()
	
	limiter = next_query[proxyid]
	proxy = proxies[proxyid]
	
	proxy = urllib.request.ProxyHandler( {} ) #{'http': proxy , 'https': proxy } )

	whois = IPWhois( str(ip), proxy_opener = proxy, allow_permutations= True )
	try:
		if item.get('legacy'):
			response = whois.lookup_whois(inc_raw = True,get_referral=True)  #, retry_count=3
		else:
			#depth means how deep to parse entities in the raw reply.
			response = whois.lookup_rdap(inc_raw = True,depth=10) #  , retry_count=3
	except ipwhois.exceptions.HTTPRateLimitError as e:
		dprint("RATELIMIT?",str(ip),whois.net.address_str)
		return True
		
	return (response,)
	
		
def whoiser_wrap(task,myid):
	
	(item,) = task
	
	proxyn = thread_to_id[myid]
	
	try:
		ret = whoiser(item,proxyn)
		if ret==True:
			return (item,True,)
			
		return (item,)+ret
	except Exception as e:
		return (item,False,e,proxies[proxyn])

	
def worker_thread():
	
	myid = threading.current_thread().ident
	
	while True:
		task = q.get()
		q.task_done()
        
		if task is None:
			break
		response = whoiser_wrap(task,myid)
		responses.put(response)

	dprint("Worker stopping...")

workers=[]
def start():
	for i in range(SIZE):
		t = threading.Thread(target=worker_thread)
		workers.append(t)
		t.daemon = True  
		t.start()
		
		id = t.ident
		assert(id)
		thread_to_id[id] = i
	
	config.monkeypatch_proxies(thread_to_id)
	
def stop():
	for i in range(SIZE):
		q.put( False, True )

def request(obj,block=False,timeout=None):
	global queries_remaining
	try:
		q.put( (obj, ) , block, timeout )
		queries_remaining+=1
		return True
	except queue.Full:
		return False

def done():
	global queries_remaining
	if queries_remaining>0:
		return False
	assert(responses.empty())
	assert(q.empty())
	
	assert(queries_remaining>=0)
	
	return True
	
def response(block=False,timeout=None):
	global queries_remaining
	try:
		resp = responses.get(  block, timeout )
		responses.task_done()
		queries_remaining-=1
		return resp
	except queue.Empty:
		return None