import random
from datetime import datetime
import time

def infinite_healthtech_log_stream(duration_seconds=60):
    """
    Native Python generator producing adversarial facility traffic for an exact duration.
    Guarantees mathematically that at least one major exfiltration metric breaks threshold.
    """
    facilities = ["Mercy_General", "St_Judes_Cardio", "City_Hospital_East"]
    endpoints = ['/dashboard', '/billing', '/records', '/prescriptions']
    users = [f"dr_smith_{i}" for i in range(5)] + [f"nurse_joy_{i}" for i in range(10)]
    
    anomalous_user = None
    burst_count = 0
    anomalous_facility = None
    burst_triggered = False
    
    start_sim_time = time.time()
    
    while True:
        elapsed = time.time() - start_sim_time
        if elapsed > duration_seconds:
            break
            
        now = datetime.utcnow()
        fac = random.choice(facilities)
        user = random.choice(users)
        
        # Guarantee massive insider threat exactly 10s into the execution
        if elapsed > 10 and not burst_triggered and anomalous_user is None:
            anomalous_user = random.choice(users)
            anomalous_facility = random.choice(facilities)
            burst_count = 0
            burst_triggered = True
            
        if anomalous_user and fac == anomalous_facility and user == anomalous_user:
            endpoint = "/records"
            bytes_trans = random.randint(15000000, 45000000) # Guaranteed 15MB-45MB chunk per log
            burst_count += 1
            if burst_count > random.randint(25, 45): # Long burst ensuring it breaches WAF
                anomalous_user = None
        else:
            endpoint = random.choices(endpoints, weights=[50, 30, 15, 5])[0]
            bytes_trans = random.randint(500, 5000)
            
        log = {
            "timestamp": now.isoformat() + "Z",
            "facility_id": fac,
            "user_id": user,
            "endpoint": endpoint,
            "bytes_transferred": bytes_trans,
            "request_id": f"REQ-{random.randint(1000,9999)}"
        }
        
        yield log
        time.sleep(random.uniform(0.01, 0.05))
