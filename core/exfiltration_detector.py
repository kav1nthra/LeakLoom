import csv
import json
import os
import hashlib
from collections import deque
from datetime import datetime
from typing import Dict, Optional, Union, List

class ExfiltrationDetector:
    """
    LeakLoom IDS: Stateful inspection engine for volume-based API exfiltration.
    Features per-user dynamic baselining and multi-dimensional threat scoring.
    """

    def __init__(self, time_window_seconds: int = 60,
                 fallback_size_bytes: int = 500 * 1024 * 1024,
                 fallback_records: int = 20) -> None:
        self.time_window_seconds = time_window_seconds
        self.fallback_size_bytes = fallback_size_bytes
        self.fallback_records = fallback_records

        self.endpoint_sensitivity = {
            "/records": 3,
            "/billing": 2,
            "/dashboard": 1
        }

        self.user_states: Dict[str, dict] = {}
        self.alerts_history: List[dict] = []

    def _parse_timestamp(self, ts_str: str) -> datetime:
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        return datetime.fromisoformat(ts_str)

    def is_unusual_time(self, timestamp: datetime) -> bool:
        return not (8 <= timestamp.hour <= 18)

    def calculate_threat_score(self, total_bytes: int, records_count: int, 
                               max_sensitivity: int, unusual_time: bool, 
                               baseline_deviation: float) -> dict:
        vol_score = min(35, (total_bytes / self.fallback_size_bytes) * 35) if self.fallback_size_bytes else 0
        freq_score = min(25, (records_count / self.fallback_records) * 25) if self.fallback_records else 0
        sens_score = min(20, (max_sensitivity / 3.0) * 20)
        
        time_penalty = 10 if unusual_time else 0
        deviation_penalty = min(10, baseline_deviation * 2) 
        anomaly_score = time_penalty + deviation_penalty

        total = int(vol_score + freq_score + sens_score + anomaly_score)
        
        return {
            "total": min(100, max(0, total)),
            "breakdown": {
                "volume": int(vol_score),
                "frequency": int(freq_score),
                "sensitivity": int(sens_score),
                "anomaly": int(anomaly_score)
            }
        }

    def process_log(self, log_entry: Union[str, dict]) -> Optional[dict]:
        if isinstance(log_entry, str):
            try:
                log_entry = json.loads(log_entry)
            except json.JSONDecodeError:
                return None

        user_id = log_entry.get("user_id")
        timestamp_str = log_entry.get("timestamp")
        endpoint = log_entry.get("endpoint")
        bytes_transferred = log_entry.get("bytes_transferred", 0)

        if not user_id or not timestamp_str:
            return None

        timestamp = self._parse_timestamp(timestamp_str)
        sensitivity = self.endpoint_sensitivity.get(endpoint, 1)

        if user_id not in self.user_states:
            self.user_states[user_id] = {
                "facility_id": log_entry.get("facility_id", "UNKNOWN"),
                "events": deque(),
                "total_bytes": 0,
                "records_count": 0,
                "currently_flagged": False,
                "max_threat_score": 0,  
                "max_subscores": {},
                "flag_count": 0,
                "highest_sensitivity_touched": 1,
                "historical_baseline_bytes": 0,
                "windows_processed": 0
            }

        state = self.user_states[user_id]

        window_start = timestamp.timestamp() - self.time_window_seconds
        
        while state["events"] and state["events"][0]["timestamp"].timestamp() < window_start:
            evicted = state["events"].popleft()
            state["total_bytes"] -= evicted["bytes_transferred"]
            if evicted["endpoint"] == "/records":
                state["records_count"] -= 1

        state["events"].append({
            "timestamp": timestamp,
            "endpoint": endpoint,
            "bytes_transferred": bytes_transferred,
            "sensitivity": sensitivity
        })

        state["total_bytes"] += bytes_transferred
        if endpoint == "/records":
            state["records_count"] += 1
            
        if sensitivity > state["highest_sensitivity_touched"]:
            state["highest_sensitivity_touched"] = sensitivity

        baseline_deviation = 0
        if state["historical_baseline_bytes"] > 0:
            if state["total_bytes"] > state["historical_baseline_bytes"]:
                baseline_deviation = state["total_bytes"] / state["historical_baseline_bytes"]
        
        if state["windows_processed"] < 100:  
            if state["historical_baseline_bytes"] == 0:
                state["historical_baseline_bytes"] = state["total_bytes"]
            else:
                alpha = 0.3
                state["historical_baseline_bytes"] = (alpha * state["total_bytes"]) + ((1 - alpha) * state["historical_baseline_bytes"])
            state["windows_processed"] += 1

        is_off_hours = self.is_unusual_time(timestamp)

        score_data = self.calculate_threat_score(
            state["total_bytes"], 
            state["records_count"], 
            state["highest_sensitivity_touched"],
            is_off_hours,
            baseline_deviation
        )

        if score_data["total"] > state["max_threat_score"]:
            state["max_threat_score"] = score_data["total"]
            state["max_subscores"] = score_data["breakdown"]

        dynamic_threshold_bytes = max(state["historical_baseline_bytes"] * 3, self.fallback_size_bytes)
        exceeds_data = state["total_bytes"] > dynamic_threshold_bytes
        exceeds_records = state["records_count"] > self.fallback_records

        if exceeds_data or exceeds_records or score_data["total"] >= 75:
            if not state["currently_flagged"]:
                state["currently_flagged"] = True
                state["flag_count"] += 1
                
                alert = {
                    "alert": "Critical Event Processed",
                    "user_id": user_id,
                    "timestamp": timestamp_str,
                    "threat_score": score_data["total"],
                    "breakdown": score_data["breakdown"],
                    "reason": "Deviation from dynamic baseline or volume exceeded",
                    "total_bytes": state["total_bytes"],
                    "records_count": state["records_count"]
                }
                self.alerts_history.append(alert)
                return alert, score_data["total"]
        else:
            state["currently_flagged"] = False

        return None, score_data["total"]

    def export_csv_report(self, output_dir: str = ".") -> None:
        os.makedirs(output_dir, exist_ok=True)
        csv_path = os.path.join(output_dir, "forensic_report.csv")

        with open(csv_path, mode='w', newline='', encoding='utf-8') as f:
            if not self.alerts_history:
                writer = csv.writer(f)
                writer.writerow(["No alerts generated."])
            else:
                fieldnames = ["timestamp", "user_id", "threat_score", "reason", "total_bytes", "records_count", "breakdown", "rolling_hash"]
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                
                prev_hash = "GENESIS_BLOCK_LEAKLOOM"
                for alert in self.alerts_history:
                    alert_csv = alert.copy()
                    alert_csv["breakdown"] = json.dumps(alert["breakdown"])
                    
                    row_data = f"{prev_hash}{alert_csv['user_id']}{alert_csv['timestamp']}{alert_csv['threat_score']}{alert_csv['total_bytes']}"
                    current_hash = hashlib.sha256(row_data.encode('utf-8')).hexdigest()
                    
                    alert_csv["rolling_hash"] = current_hash
                    prev_hash = current_hash
                    
                    writer.writerow(alert_csv)

    def get_threat_summary_dict(self) -> dict:
        summary = {"total_users": len(self.user_states), "users": []}
        for uid, state in self.user_states.items():
            if state["max_threat_score"] > 0 or state["flag_count"] > 0:
                summary["users"].append({
                    "user_id": uid,
                    "facility_id": state.get("facility_id", "UNKNOWN"),
                    "max_threat_score": state["max_threat_score"],
                    "flag_count": state["flag_count"],
                    "subscores": state["max_subscores"]
                })
        summary["users"].sort(key=lambda x: x["max_threat_score"], reverse=True)
        return summary

    def export_json_summary(self, output_dir: str = ".") -> None:
        os.makedirs(output_dir, exist_ok=True)
        json_path = os.path.join(output_dir, "threat_summary.json")
        
        summary = self.get_threat_summary_dict()
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=4)
