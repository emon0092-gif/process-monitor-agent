import wmi

def get_services():
    c = wmi.WMI()
    services = []
    
    for service in c.Win32_Service():
        services.append({
            "name": service.Name,
            "path": service.PathName
        })
    
    return services


def detect_suspicious_services(services):
    alerts = []
    
    for s in services:
        if s["path"] and "Temp" in s["path"]:
            alerts.append(f"[HIGH] Suspicious Service: {s['name']}")
    
    return alerts
