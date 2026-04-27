from process_monitor import get_processes
from detector import detect_parent_child, detect_unknown, detect_temp_path
from service_monitor import get_services, detect_suspicious_services
from logger import log_event
import time

print("🚀 Process Monitoring Agent Started...\n")

while True:
    processes = get_processes()
    services = get_services()

    alerts = []
    alerts += detect_parent_child(processes)
    alerts += detect_unknown(processes)
    alerts += detect_temp_path(processes)
    alerts += detect_suspicious_services(services)

    for alert in alerts:
        print(alert)
        log_event(alert)

    time.sleep(5)
