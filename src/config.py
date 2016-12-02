
import urllib
import urllib.request
from pprint import pprint
proxies = [
	'',
	''
]


_tested_proxies = False
def test_proxies():
	global _tested_proxies
	
	if _tested_proxies:
		return
	
	_tested_proxies = {}
	
	def _testproxy(proxyid):
		if proxyid=='':
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
	