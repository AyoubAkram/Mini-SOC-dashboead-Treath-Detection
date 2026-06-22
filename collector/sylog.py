import subprocess
import sys
from pathlib import Path

# Add backend to path to import ingestion module
sys.path.insert(0, str(Path(__file__).parent.parent))
from backend.ingestion import ingest_log
def parser(Line):
    print(Line)
    
def SyLogs ():
    process = subprocess.Popen(['cat', '/var/log/syslog'], stdout=subprocess.PIPE, text=True)

    for line in process.stdout:
        parser(line)
        
        
def LiveSysLogs ():
    process = subprocess.Popen(['tail', '-f', '/var/log/syslog'], stdout=subprocess.PIPE, text=True)

    for line in process.stdout:
        parser(line)
        
        
def ServicesFilter (ServiceName):
    process = subprocess.Popen(['grep', ServiceName, '/var/log/syslog'], stdout=subprocess.PIPE, text=True)
    for line in process.stdout:
        parser(line)
        
        
def ErrorLogs ():
    process = subprocess.Popen(['grep','-i', 'error', '/var/log/syslog'], stdout=subprocess.PIPE, text=True)
    for line in process.stdout:
        parser(line)
        
        
def main():
    LiveSysLogs()
    
if __name__ == "__main__":
    main()