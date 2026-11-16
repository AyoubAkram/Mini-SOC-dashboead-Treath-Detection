import subprocess
import sys
from pathlib import Path

# Add backend to path to import ingestion module
sys.path.insert(0, str(Path(__file__).parent.parent))
from backend.ingestion import LogBatcher

# Lines are buffered and ingested in batches (one integrity hash per batch)
batcher = LogBatcher("syslog")

def parser(Line):
    batcher.add(Line)
    
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
    try:
        LiveSysLogs()
    except KeyboardInterrupt:
        pass
    finally:
        batcher.close()
    
if __name__ == "__main__":
    main()
