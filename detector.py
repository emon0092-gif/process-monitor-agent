import psutil
WHITELIST = ["explorer.exe","chrome.exe","svchost.exe","cmd.exe"]
def detect_parent_child(processes):
    alerts = []  
    for proc in processes:
        try:
            parent = psutil.Process(proc['ppid']).name()
            child = proc['name']

            if parent == "winword.exe" and child == "powershell.exe":
                alerts.append(f"[HIGH] Suspicious: {parent} → {child}")
        except:
            pass
    
    return alerts


def detect_unknown(processes):
    alerts = []
    
    for proc in processes:
        if proc['name'] not in WHITELIST:
            alerts.append(f"[MEDIUM] Unknown process: {proc['name']}")
    
    return alerts


def detect_temp_path(processes):
    alerts = []
    
    for proc in processes:
        path = proc.get('exe')
        
        if path and "Temp" in path:
            alerts.append(f"[HIGH] Running from Temp: {proc['name']}")
    
    return alerts
