
### installing to virtualenv

```
python -m venv .venv/<dir>
OR:
apt-get install virtualenv
virtualenv .venv/<dir>

source .venv<dir>/bin/activate
git clone <repo>; cd <repo>
python setup.py install
python kerbrute.py -h
OR:
pip3 install <package>
python kerbrute.py -h
...
deactivate
```


### TLS connection via python (no cert validation)

This is the same as -k with curl and -–no-check-certificate for wget.

```
import urllib2
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

urllib2.urlopen("https://your-test-server.local", context=ctx)
```

### local HTTP server

python 2:

    $ python -m SimpleHTTPServer 8080

static content only:

    $ python3 -m http.server --bind 0.0.0.0 8079

CGI server:

    $ mkdir cgi-bin  
    $ vi cgi-bin/stb14.sh # put script from this challenge here  
    $ python3 -m http.server --cgi 8000

### local HTTP server with CORS * enabled

```
#! /usr/bin/env python3

import http.server
import socketserver

# To handle CGI scripts change SimpleHTTPRequestHandler to CGIHTTPRequestHandler

PORT = 8000

class CORSRequestHandler (http.server.SimpleHTTPRequestHandler):
    def end_headers (self):
        self.send_header('Access-Control-Allow-Origin', '*')
        http.server.SimpleHTTPRequestHandler.end_headers(self)

if __name__ == '__main__':

    Handler = CORSRequestHandler

    httpd = socketserver.TCPServer(("", PORT), Handler)

    print("serving at port", PORT)
    httpd.serve_forever()
```

### HTTPS server

```
#! /usr/bin/env python3

import http.server
import socketserver
import ssl

# certificate generation
# $ openssl req -new -x509 -keyout localhost.pem -out localhost.pem -days 365 -nodes

PORT = 4443 

if __name__ == '__main__':

    Handler = http.server.SimpleHTTPRequestHandler

    httpd = socketserver.TCPServer(("", PORT), Handler)
    httpd.socket = ssl.wrap_socket(httpd.socket, certfile='./localhost.pem', server_side=True)
    httpd.serve_forever()
```

### HTTP proxy

```
#! /usr/bin/env python3
# Usage:
# curl -x localhost:8080 http://wp.pl

import http.server
import socketserver
import urllib.request

PORT = 8080

class ProxyRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.copyfile(urllib.request.urlopen(self.path), self.wfile)

if __name__ == '__main__':

    Handler = ProxyRequestHandler

    httpd = socketserver.ForkingTCPServer(("", PORT), Handler)

    print("serving at port", PORT)
    httpd.serve_forever()
```

### HTTP server with authentication

```
#! /usr/bin/env python

import BaseHTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
import sys
import base64

key = ""

class AuthHandler(SimpleHTTPRequestHandler):
    ''' Main class to present webpages and authentication. '''
    def do_HEAD(self):
        print "send header"
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_AUTHHEAD(self):
        print "send header"
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Test\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        global key
        ''' Present frontpage with user authentication. '''
        if self.headers.getheader('Authorization') == None:
            self.do_AUTHHEAD()
            self.wfile.write('no auth header received')
            pass
        elif self.headers.getheader('Authorization') == 'Basic '+key:
            SimpleHTTPRequestHandler.do_GET(self)
            pass
        else:
            self.do_AUTHHEAD()
            self.wfile.write(self.headers.getheader('Authorization'))
            self.wfile.write('not authenticated')
            pass

def test(HandlerClass = AuthHandler,
         ServerClass = BaseHTTPServer.HTTPServer):
    BaseHTTPServer.test(HandlerClass, ServerClass)


if __name__ == '__main__':
    if len(sys.argv)<3:
        print "usage SimpleAuthServer.py [port] [username:password]"
        sys.exit()
    key = base64.b64encode(sys.argv[2])
test()
```

### xor two strings of different lengths

```
#! /usr/bin/env python

import sys
import binascii

# xor two strings of different lengths
def strxor(a, b):     
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

if __name__ == "__main__":

    if len(sys.argv) < 3:
        print "usage: ./xor.py <str1> <str2>"
    else:
        res = strxor(binascii.unhexlify(sys.argv[1]), binascii.unhexlify(sys.argv[2]))
        print res.encode('hex')
```


