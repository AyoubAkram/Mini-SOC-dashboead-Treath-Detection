import subprocess
import sys
from pathlib import Path

# Add backend to path to import ingestion module
sys.path.insert(0, str(Path(__file__).parent.parent))
from backend.ingestion import ingest_log

def parser(Line):
    print(Line)

def liveJournalLogs ():
    process = subprocess.Popen(['journalctl', '-f', '-o', 'json'], stdout=subprocess.PIPE, text=True)

    for line in process.stdout:
        parser(line)


def currentBootInvestigations ():
    process = subprocess.Popen(['journalctl', '-b', '-o', 'json'], stdout=subprocess.PIPE, text=True)
    for line in process.stdout:
        parser(line)


#this function is for ssh logs and sudo logs
def ScruityLogs ():
    ServicesFilter('ssh')
    process = subprocess.Popen(['journalctl', '_COMM=sudo', '-o', 'json'], stdout=subprocess.PIPE, text=True)
    for line in process.stdout:
        parser(line)

def ServicesFilter (ServiceName):
    process = subprocess.Popen(['journalctl', '-u', ServiceName, '-o', 'json'], stdout=subprocess.PIPE, text=True)
    for line in process.stdout:
        parser(line)

        
def main():
    liveJournalLogs()
    
if __name__ == "__main__":
    main()