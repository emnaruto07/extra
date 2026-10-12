#!/usr/bin/env python3
"""Fake internal-app HTTP servers to test adenum web fingerprinting."""
import http.server
import threading

PAGES = {
    5000: ('Apache-Coyote/1.1',
           '<html><head><title>Apache Tomcat/7.0.109</title></head>'
           '<body>manager/html</body></html>'),
    7001: ('Jetty',
           '<html><head><title>Dashboard [Jenkins]</title></head>'
           '<body data-version="2.440" x-jenkins="2.440"></body></html>'),
    8888: ('Grafana',
           '<html><head><title>Grafana</title></head></html>'),
    9000: ('nginx',
           '<html><head><title>Index of /</title></head>'
           '<body><h1>Index of / backups/ scripts/</h1></body></html>'),
    9090: ('Microsoft-IIS/10.0',
           '<html><head><title>Outlook Web App</title></head></html>'),
    8081: ('nginx',
           '<html><head><title>GitLab</title></head></html>'),
}

def make_handler(server_hdr, body):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Server', server_hdr)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(body.encode())
        def log_message(self, *a):
            pass
    return H

servers = []
for port, (hdr, body) in PAGES.items():
    httpd = http.server.HTTPServer(('127.0.0.1', port), make_handler(hdr, body))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    servers.append(httpd)
    print('serving %d: %s' % (port, hdr))

# keep alive
import time
while True:
    time.sleep(60)