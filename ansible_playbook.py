import logging
import subprocess
import os
import time 


MAX_RETRIES = 6
DELAY_SECONDS = 5



def ping_hosts(tag):
    try:
        ansible_command = f"ansible all --ssh-common-args '-F {tag}_config' -i hosts -m ping"
        result = subprocess.run(
            ansible_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell = True,
            text = True
        )
        output = result.stdout + result.stderr
        
        if "UNREACHABLE" in output or "FAILED" in output:
            return False
        return True
    except Exception as e:
        print(f"Error running Ansible: {e}")
        return False

def ansible_ping(tag):
    # Get the directory where the script is located
    script_dir = os.path.dirname(__file__)
    ansible_inventory_path = os.path.join(script_dir, f"{tag}_config")
    for attempt in range(1, MAX_RETRIES + 1):
        print(f"\n Attempt {attempt} of {MAX_RETRIES}")
        success = ping_hosts(tag)
        if success:
            print("All hosts are reachable.")
            return True
        else:
            if attempt < MAX_RETRIES:
                print(f"Some hosts unreachable. Retrying in {DELAY_SECONDS} seconds...")
                time.sleep(DELAY_SECONDS)
            else:
                print(" Maximum retries reached. Hosts still unreachable.")
    return False

def run_playbook(tag, virtual_ip = None):
    logging.info("Running Ansible playbook...")
    
    # Get the directory where the script is located
    script_dir = os.path.dirname(__file__)
    ansible_inventory_path = os.path.join(script_dir, f"{tag}_config")

    ansible_command = f"ansible-playbook  --ssh-common-args '-F {tag}_config' -i hosts  site.yaml -e 'virtual_ip={virtual_ip}'"
    subprocess.run(ansible_command, shell=True)
    logging.info("Ansible playbook execution complete.")