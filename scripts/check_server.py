import urllib.request
try:
    r = urllib.request.urlopen('http://localhost:3000', timeout=5)
    print('HTTP', r.getcode())
    print('Content-Type:', r.headers.get('Content-Type'))
except Exception as e:
    print('ERROR', e)
