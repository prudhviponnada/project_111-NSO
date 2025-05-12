import subprocess
import os

def load_openrc(openrc):
    command = f"bash -c 'source {openrc} && env'"
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    for line in proc.stdout:
        (key, _, value) = line.decode("utf-8").partition("=")
        os.environ[key] = value.strip()
    proc.communicate()