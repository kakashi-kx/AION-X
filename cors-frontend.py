#!/usr/bin/env python3
"""
CORS-enabled frontend server for AION-X with increased timeouts
"""

import http.server
import socketserver
import urllib.request
import urllib.parse
import json
import socket
from urllib.parse import urlparse, parse_qs

PORT = 3000
API_BACKEND = "http://localhost:8000"
TIMEOUT = 60  # Increase timeout to 60 seconds

# Create a custom opener with longer timeouts
opener = urllib.request.build_opener()
opener.addheaders = [('User-agent', 'AION-X-Proxy/1.0')]
urllib.request.install_opener(opener)

class CORSProxyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Accept, Authorization')
        self.send_header('Access-Control-Allow-Credentials', 'true')
        super().end_headers()
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()
    
    def do_GET(self):
        if self.path.startswith('/api/'):
            self.proxy_request('GET')
        else:
            if self.path == '/':
                self.path = '/index.html'
            try:
                super().do_GET()
            except Exception as e:
                print(f"Error serving static file: {e}")
                self.send_error(404)
    
    def do_POST(self):
        if self.path.startswith('/api/'):
            self.proxy_request('POST')
        else:
            self.send_error(404, "Not found")
    
    def proxy_request(self, method):
        try:
            # Extract the API path (remove '/api' prefix)
            api_path = self.path[4:]  # Remove '/api'
            target_url = f"{API_BACKEND}{api_path}"
            
            print(f"🔄 Proxying {method} request to: {target_url}")
            
            # Get content length and body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else None
            
            # Create proxy request with timeout
            req = urllib.request.Request(
                target_url,
                data=body,
                method=method,
                headers={
                    'Content-Type': self.headers.get('Content-Type', 'application/json'),
                    'Accept': 'application/json'
                }
            )
            
            # Send request to backend with timeout
            response = urllib.request.urlopen(req, timeout=TIMEOUT)
            
            # Read response
            response_data = response.read()
            
            # Send response back to client
            self.send_response(response.status)
            self.send_header('Content-Type', response.headers.get('Content-Type', 'application/json'))
            self.end_headers()
            self.wfile.write(response_data)
            
            print(f"✅ Proxy successful: {response.status}")
                
        except socket.timeout:
            print(f"❌ Proxy timeout after {TIMEOUT} seconds")
            self.send_error(504, f"Gateway timeout after {TIMEOUT} seconds")
        except urllib.error.URLError as e:
            print(f"❌ Proxy URL error: {e}")
            if hasattr(e, 'reason'):
                self.send_error(502, f"Backend error: {e.reason}")
            else:
                self.send_error(502, f"Backend error: {str(e)}")
        except Exception as e:
            print(f"❌ Proxy error: {e}")
            self.send_error(500, f"Proxy error: {str(e)}")

if __name__ == '__main__':
    import os
    import sys
    
    # Change to frontend directory to serve files
    frontend_dir = os.path.join(os.path.dirname(__file__), 'frontend')
    if os.path.exists(frontend_dir):
        os.chdir(frontend_dir)
        print(f"📁 Serving frontend files from: {frontend_dir}")
    else:
        print(f"⚠️ Frontend directory not found at: {frontend_dir}")
        print(f"📁 Serving from current directory: {os.getcwd()}")
    
    print(f"🚀 AION-X Frontend with CORS Proxy")
    print(f"🔄 Proxying API requests to: {API_BACKEND}")
    print(f"⏱️  Timeout: {TIMEOUT} seconds")
    print(f"🌐 Access at: http://localhost:{PORT}")
    print(f"📝 Press Ctrl+C to stop")
    
    # Allow address reuse
    socketserver.TCPServer.allow_reuse_address = True
    
    with socketserver.TCPServer(('', PORT), CORSProxyHTTPRequestHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n👋 Shutting down frontend server...")
            httpd.shutdown()
