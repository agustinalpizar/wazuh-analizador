"""Servidor local SOLO en 127.0.0.1 que desactiva la cache, para ver siempre la ultima version."""
import functools, http.server, os, sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
ROOT = os.path.dirname(os.path.abspath(__file__))

class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

if __name__ == "__main__":
    handler = functools.partial(Handler, directory=ROOT)
    with http.server.ThreadingHTTPServer(("127.0.0.1", PORT), handler) as srv:
        print(f"Sirviendo {ROOT} en http://127.0.0.1:{PORT}/index.html  (Ctrl+C para detener)")
        srv.serve_forever()
