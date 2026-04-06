import pytest
from datetime import datetime, timedelta
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.exfiltration_detector import ExfiltrationDetector

def test_cold_start_exceeds_fallback():
    detector = ExfiltrationDetector()
    
    log = {
        "timestamp": "2026-04-06T12:00:00Z",
        "user_id": "test_burst",
        "endpoint": "/billing",
        "bytes_transferred": 600 * 1024 * 1024 # 600 MB
    }
    alert, score = detector.process_log(log)
    assert alert is not None
    assert alert["reason"] == "Deviation from dynamic baseline or volume exceeded"

def test_off_hours_penalty():
    detector = ExfiltrationDetector()
    
    log_off = {
        "timestamp": "2026-04-06T03:00:00Z",
        "user_id": "night_owl",
        "endpoint": "/dashboard",
        "bytes_transferred": 1000
    }
    detector.process_log(log_off)
    score_off = detector.user_states["night_owl"]["max_threat_score"]
    
    detector = ExfiltrationDetector()
    log_on = {
        "timestamp": "2026-04-06T12:00:00Z",
        "user_id": "day_user",
        "endpoint": "/dashboard",
        "bytes_transferred": 1000
    }
    detector.process_log(log_on)
    score_on = detector.user_states["day_user"]["max_threat_score"]
    
    assert score_off > score_on

def test_burst_frequency_records():
    detector = ExfiltrationDetector(fallback_records=5)
    
    alerts = []
    base_time = datetime(2026, 4, 6, 12, 0, 0)
    for i in range(10): 
        log = {
            "timestamp": (base_time + timedelta(seconds=i)).isoformat() + "Z",
            "user_id": "scraper",
            "endpoint": "/records",
            "bytes_transferred": 100
        }
        res, score = detector.process_log(log)
        if res:
            alerts.append(res)
            
    assert len(alerts) == 1
    assert alerts[0]["records_count"] == 6

def test_dynamic_baselining():
    detector = ExfiltrationDetector()
    
    base_time = datetime(2026, 4, 6, 12, 0, 0)
    for i in range(10):
        log = {
            "timestamp": (base_time + timedelta(seconds=i)).isoformat() + "Z",
            "user_id": "steady_user",
            "endpoint": "/dashboard",
            "bytes_transferred": 1000  
        }
        detector.process_log(log)
        
    baseline_before = detector.user_states["steady_user"]["historical_baseline_bytes"]
    assert baseline_before > 0
    
    burst_log = {
        "timestamp": (base_time + timedelta(seconds=11)).isoformat() + "Z",
        "user_id": "steady_user",
        "endpoint": "/dashboard",
        "bytes_transferred": 500000 
    }
    
    score_before = detector.user_states["steady_user"]["max_threat_score"]
    detector.process_log(burst_log)
    score_after = detector.user_states["steady_user"]["max_threat_score"]
    assert score_after > score_before

def test_hash_chain_integrity():
    import csv, hashlib, tempfile, os
    detector = ExfiltrationDetector()
    detector.process_log({"timestamp":"2026-04-06T12:00:00Z","user_id":"x","endpoint":"/records","bytes_transferred":600*1024*1024})
    
    with tempfile.TemporaryDirectory() as tmp:
        detector.export_csv_report(tmp)
        path = os.path.join(tmp, "forensic_report.csv")
        with open(path) as f:
            rows = list(csv.DictReader(f))
    
    prev = "GENESIS_BLOCK_LEAKLOOM"
    for row in rows:
        expected = hashlib.sha256(
            f"{prev}{row['user_id']}{row['timestamp']}{row['threat_score']}{row['total_bytes']}".encode('utf-8')
        ).hexdigest()
        assert row["rolling_hash"] == expected
        prev = expected

def test_zero_false_positives():
    detector = ExfiltrationDetector()
    base_time = datetime(2026, 4, 6, 12, 0, 0)
    
    alerts = []
    for i in range(1000):
        log = {
            "timestamp": (base_time + timedelta(seconds=i)).isoformat() + "Z",
            "user_id": f"legit_user_{i % 50}",
            "endpoint": "/dashboard",
            "bytes_transferred": 500  
        }
        res, score = detector.process_log(log)
        if res:
            alerts.append(res)
            
    assert len(alerts) == 0 
