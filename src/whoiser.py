import threading
import queue
from queue import Queue
import time
from ipwhois import IPWhois
import netaddr

SIZE = 2

#TODO
proxies=[
	["127.0.0.1:1234"],
]

# Synchronized map?
next_query=[
	#for each endpoint ip (proxies)
	{
		"whois.arin.net": 0,
		"whois.ripe.net": 0,
	}
]

queries_remaining=0
q = Queue(maxsize=SIZE*2+1)
responses = Queue(maxsize=SIZE *2+1)
printlock = threading.Lock()

def dprint(*args, **kwargs):
	with printlock:
		print(*args, **kwargs)

def whoiser(task):
	
	(item,) = task
	
	
	try:
		ip = netaddr.IPAddress(item['ip'])
		dprint("Processing",str(ip))
		
		whois = IPWhois( str(ip), proxy_opener = None, allow_permutations= True )
		response = item.get('legacy') and whois.lookup_whois(inc_raw = True,get_referral=True, retry_count=1) or whois.lookup_rdap(retry_count=1,depth=4,)
		return (item,response,)
		
	except Exception as e:
		dprint("Whois failed for",str(ip),e)
		return (item,False,e,)

	
def worker_thread():
	while True:
		task = q.get()
		q.task_done()
        
		if task is None:
			break
		response = whoiser(task)
		responses.put(response)

	dprint("Worker stopping...")

workers=[]
def start():
	for i in range(SIZE):
		t = threading.Thread(target=worker_thread)
		workers.append(t)
		t.daemon = True  
		t.start()

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