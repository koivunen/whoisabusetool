
if __name__ == "__main__":
	import sys
	print(sys.version)
	
import urllib
import urllib.request

import socket
import socks
import threading

from pprint import pprint
proxies = [
	True,
	True
]



			
_tested_proxies = False
def test_proxies():
	global _tested_proxies
	
	if _tested_proxies:
		return
	
	_tested_proxies = {}
	
	def _testproxy(proxyid):
		if proxyid==True:
			return True
			
		if _tested_proxies.get(proxyid) is not None:
			return _tested_proxies.get(proxyid)

		print("Pretesting proxy",proxyid)
		proxy = urllib.request.ProxyHandler( {'http': proxyid , 'https': proxyid } )
		opener = urllib.request.build_opener(proxy)
		#urllib.request.install_opener(opener)
		try:
			opened = opener.open('http://example.com')
			if not opened:
				_tested_proxies[proxyid] = False
				return False
			assert(opened.read().find(b"Example Domain")>-1)
			
		except urllib.error.URLError as e:
			try:
				opened = opener.open('http://google.com')
				if not opened:
					print("FAIL")
					_tested_proxies[proxyid] = False
					return False
				
			except urllib.error.URLError as e:
				print("Proxy error",proxyid,e)
				_tested_proxies[proxyid] = False
				return False
				
		_tested_proxies[proxyid] = True
		return True	

	proxies[:] = [tup for tup in proxies if _testproxy(tup)]
	
	_tested_proxies = True

import re
def monkeypatch_proxies(thread_to_proxy):
	
	class socksocket2(socks.socksocket):
		def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, *args, **kwargs):
			socks.socksocket.__init__(self, family, type, proto, *args, **kwargs)
			#try:
			proxyid = thread_to_proxy[threading.current_thread().ident]
			
			proxy = proxies[proxyid]
			
			#print("Newsocket",proxyid,proxy)
			
			if proxy==True:
				pass
			else:
				(ip,port,) = re.search(r"(\d*\.\d*\.\d*\.\d*)\:(\d+)",proxy).groups()
				port = int(port)
				self.set_proxy(socks.HTTP, ip,port)

			#except Exception as e:
			#	print(e)
			
	socket.socket = socksocket2

if __name__ == "__main__":
	
	test_proxies()
	pprint(proxies)