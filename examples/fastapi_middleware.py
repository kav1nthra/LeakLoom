"""
LeakLoom FastAPI Middleware Example
-----------------------------------
This file demonstrates how seamlessly LeakLoom embeds into modern Python web stacks.
It functions perfectly as lightweight middleware analyzing the traffic stream asynchronously.
"""

from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from datetime import datetime
import json
import time
import sys
import os

# Add parent to path for testing example script from subfolder
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the core engine perfectly
from core.exfiltration_detector import ExfiltrationDetector

app = FastAPI(title="LeakLoom Protected API")

# Initialize a global threat engine instance
leakloom_engine = ExfiltrationDetector(
    time_window_seconds=60,
    fallback_size_bytes=500 * 1024 * 1024,
    fallback_records=20
)

class LeakLoomMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        
        # Process the downstream request natively
        response = await call_next(request)
        
        # In a real app, user_id comes from JWT or Session token
        user_id = getattr(request.state, "user", "anonymous_session")
        
        # Calculate outbound bandwidth usage
        content_length = int(response.headers.get("content-length", 0))

        # Build log telemetry for the IDS
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "user_id": user_id,
            "endpoint": request.url.path,
            "bytes_transferred": content_length,
            "request_id": request.headers.get("X-Request-ID", "unknown")
        }

        # Non-blocking analysis
        # Feed the log directly into LeakLoom RAM state
        alert = leakloom_engine.process_log(log_entry)

        if alert:
            # Anomaly trigger! You could trigger webhooks, push to Slack, or throttle API
            print(f"🚨 [LEAKLOOM TRIGGER] {alert['user_id']} flagged with Threat Score {alert['threat_score']}!")
            
        return response

app.add_middleware(LeakLoomMiddleware)

@app.get("/records")
async def fetch_records():
    return {"data": ["record_payload"] * 5000}

@app.get("/dashboard")
async def view_dashboard():
    return {"status": "User Dashboard Loaded"}

if __name__ == "__main__":
    print("Run this file natively via uvicorn")
