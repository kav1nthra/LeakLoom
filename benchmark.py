import tracemalloc
import time
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from core.exfiltration_detector import ExfiltrationDetector
from core.healthtech_log_gen import generate_healthtech_logs

def run_benchmark():
    print("Generating 10,000 rigorous API logs...")
    logs = generate_healthtech_logs(total_logs=10000)
    detector = ExfiltrationDetector()

    print("Running memory profiling...")
    tracemalloc.start()
    start_t = time.time()

    for log in logs:
        detector.process_log(log)

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    duration = time.time() - start_t

    print(f"\n--- LeakLoom Tracemalloc Benchmark ---")
    print(f"Events Processed: 10,000 API payloads")
    print(f"Total Execution Time: {duration:.3f} seconds")
    print(f"Peak Memory Footprint: {peak / 1024 / 1024:.3f} MB")
    print(f"Current Memory Usage: {current / 1024 / 1024:.3f} MB")
    print(f"--------------------------------------\n")

if __name__ == "__main__":
    run_benchmark()
