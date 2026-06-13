import subprocess 

process = subprocess.Popen(['journalctl', '-F' , '-o' , 'json' ], stdout=subprocess.PIPE, text=True)

for line in process.stdout:
    print(line)