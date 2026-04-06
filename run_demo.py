import os
import json
import time
import http.server
import socketserver
import threading
import queue
from core.healthtech_log_gen import infinite_healthtech_log_stream
from core.exfiltration_detector import ExfiltrationDetector

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_DIR = os.path.join(PROJECT_ROOT, "dashboard")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")

clients = []

detector = ExfiltrationDetector()

def run_simulation_engine():
    print("[+] Engine Native Thread Activated - Running 60-Second Live Multi-Tenant Execution...")
    stream = infinite_healthtech_log_stream(duration_seconds=60)
    
    last_summary_time = time.time()
    
    for log in stream:
        alert, current_score = detector.process_log(log)
        
        if current_score >= 50:
            print(f"[WAF ENGINE] {log['facility_id']} | {log['user_id']} | Threat Score: {current_score}")
            
        # Broadcast the raw log telemetry directly down the SSE WebSocket-style pipe
        payload = json.dumps({"type": "telemetry", "data": log})
        broadcast(f"data: {payload}\n\n")
        
        # Periodically or critically push threat summary matrix updates identically to WAF architectures.
        if alert or (time.time() - last_summary_time > 0.5):
            summ_payload = json.dumps({"type": "summary", "data": detector.get_threat_summary_dict()})
            broadcast(f"data: {summ_payload}\n\n")
            last_summary_time = time.time()
            
        # Natively save historical compliance reports routinely
        if alert:
            detector.export_csv_report(LOGS_DIR)
            
    print("\n[+] 60-Second Execution Completed. Server remains online for Dashboard Post-Mortem Analysis.")

def broadcast(msg: str):
    for q in list(clients):
        try:
            q.put_nowait(msg)
        except queue.Full:
            pass

class SSEHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DASHBOARD_DIR, **kwargs)
        
    def end_headers(self):
        if self.path != '/stream':
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        super().end_headers()
        
    def do_GET(self):
        if self.path == '/stream':
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.send_header('Access-Control-Allow-Origin', '*')
            # SimpleHTTPRequestHandler end_headers doesn't get called if we skip super().do_GET(), so we manual flush
            self.end_headers()
            
            client_queue = queue.Queue(maxsize=1000)
            clients.append(client_queue)
            
            try:
                while True:
                    msg = client_queue.get()
                    self.wfile.write(msg.encode('utf-8'))
                    self.wfile.flush()
            except Exception:
                clients.remove(client_queue)
        else:
            super().do_GET()

def start_server():
    PORT = 8080
    # Enable threading over standard execution allowing Background Generator & Realtime Web serving 
    threading.Thread(target=run_simulation_engine, daemon=True).start()
    
    print(f"\n[+] LeakLoom V3 SSE Multi-Tenant Server active at http://localhost:{PORT}")
    with socketserver.ThreadingTCPServer(("", PORT), SSEHandler) as httpd:
        # Avoid hanging standard ports
        httpd.allow_reuse_address = True 
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down WAF SSE Pipeline gracefully.")

if __name__ == "__main__":
    os.makedirs(LOGS_DIR, exist_ok=True)
    start_server()
