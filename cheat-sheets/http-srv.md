
# HTTP service deployments

## HTTP server

### Simplest

Use burp (see [here](https://blog.z-labs.eu/2019/09/09/burp-suite-pro-rltandt-collaborator-presistence.html) for Persistent Access to Collaborator):

    Burp -> Burp Collaborator client

Not really HTTP but simple TCP listeners:

With `nc`: `while true; do nc -nvlp 4444; done`

With Nmap's `Ncat`: `ncat -nv -k -l -p 4444`

Python2 builtin:

    python2 -m SimpleHTTPServer 8080

Python3 builtin:

    python3 -m http.server --bind 0.0.0.0 8080

### HTTPS server as code in Python3

```
cat > https-srv.py << EOF
#! /usr/bin/env python3

import http.server
import socketserver
import ssl

# certificate generation:
# $ openssl req -new -x509 -keyout localhost.pem -out localhost.pem -days 365 -nodes

PORT = 4443 

if __name__ == '__main__':

    Handler = http.server.SimpleHTTPRequestHandler

    httpd = socketserver.TCPServer(("", PORT), Handler)
    httpd.socket = ssl.wrap_socket(httpd.socket, certfile='./localhost.pem', server_side=True)
    httpd.serve_forever()
EOF
```

## Certificates

Self-signed:

    openssl req -new -x509 -keyout key.pem -out cert.pem -days 365 -nodes

Let's encrypt:

Manually create cert (DNS for the domain name to be certified needs to be already set up), then:

```
certbot certonly --manual --register-unsafely-without-email

# in second terminal:
mkdir -p wwwroot/.well-known/acme-challenge/
echo -n '<id>' > wwwroot/.well-known/acme-challenge/<filename>
cd wwwroot; python2 -m SimpleHTTPServer 80

# test
cp /etc/letsencrypt/live/<domain-name>/fullchain.pem cert.pem
cp /etc/letsencrypt/live/<domain-name>/key.pem key.pem
ncat --ssl-cert cert.pem --ssl-key key.pem -nv -l -p 443 -k
```

## DNS server
