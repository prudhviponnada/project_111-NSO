import os
import sys
import subprocess
import re
import time
import datetime

def get_current_time():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def check_server_status(server_name):
    result = subprocess.run(f"openstack server show {server_name}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return "ACTIVE" in result.stdout

def execute_ansible_tasks():
    ansible_command = "ansible-playbook -i hosts site.yaml"
    subprocess.run(ansible_command, shell=True)
    print("Executing Ansible tasks...")

def validate_keypair(key_name):
    result = subprocess.run("openstack keypair list -f value -c Name", shell=True, stdout=subprocess.PIPE, text=True)
    keypairs = result.stdout.splitlines()
    return key_name in keypairs

def get_fixed_ip(server_name):
    try:
        command = f"openstack server show {server_name} -c addresses"
        output = subprocess.check_output(command, shell=True).decode().strip().split('\n')
        return output[3].split('=')[1].strip().rstrip('|')
    except subprocess.CalledProcessError as e:
        print(f"{get_current_time()}: Failed to get IP for {server_name}. Error: {str(e)}")
        return None

# Parse command-line arguments
openrc_file = sys.argv[1]
tag = sys.argv[2]
ssh_key = sys.argv[3]

# Validate the existence of the provided files
if not os.path.isfile(openrc_file):
    print(f"Error: The file '{openrc_file}' does not exist.")
    sys.exit(1)

if not os.path.isfile(ssh_key):
    print(f"Error: The file '{ssh_key}' does not exist.")
    sys.exit(1)

# Load environment variables from the OpenRC file
from dotenv import load_dotenv
load_dotenv(openrc_file)

# Validate keypair
key_name = f"{tag}_key"
if not validate_keypair(key_name):
    print(f"{get_current_time()}: Error: The keypair '{key_name}' does not exist. Please create it or use a valid keypair.")
    sys.exit(1)

# Generate server names based on the provided tag
server_names = [f"{tag}_node{i+1}" for i in range(10)]

while True:
    with open('server.conf', 'r') as file:
        config_lines = file.readlines()

    num_nodes = None
    for line in config_lines:
        if "num_nodes =" in line:
            match = re.search(r'num_nodes = (\d+)', line)
            if match:
                num_nodes = int(match.group(1))
            break

    if num_nodes is None:
        print(f"{get_current_time()}: Could not determine the number of required nodes from server.conf.")
        sys.exit(1)

    print(f"{get_current_time()}: Server configuration requires {num_nodes} nodes.")

    result = subprocess.run("openstack server list -c Name -f value", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    existing_nodes = re.findall(rf"^{tag}_node\d+", result.stdout, re.MULTILINE)
    print(f"{get_current_time()}: Found {len(existing_nodes)} existing nodes. Sleeping for 30 seconds...")
    time.sleep(30)

    if len(existing_nodes) == num_nodes:
        config_lines = [line.replace(f"num_nodes = {num_nodes}", f"num_nodes = {num_nodes + 1}") for line in config_lines]
        with open('server.conf', 'w') as file:
            file.writelines(config_lines)
        time.sleep(30)
    elif len(existing_nodes) > num_nodes:
        excess_nodes = len(existing_nodes) - num_nodes
        print(f"{get_current_time()}: There are {excess_nodes} excess nodes.")

        existing_nodes.sort(reverse=True)
        removed_count = 0

        for node in existing_nodes:
            if removed_count >= excess_nodes:
                break

            result = subprocess.run(f"openstack server delete {node}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            time.sleep(20)

            if result.returncode == 0:
                removed_count += 1
                print(f"{get_current_time()}: Successfully deleted {node}.")
            else:
                print(f"{get_current_time()}: Failed to delete {node}. Error: {result.stderr}")
    else:
        missing_nodes = num_nodes - len(existing_nodes)
        missing_server_names = [name for name in server_names if name not in existing_nodes]

        for name, _ in zip(missing_server_names, range(missing_nodes)):
            print(f"{get_current_time()}: Creating missing node: {name}.")
            create_command = f"openstack server create --image 'Ubuntu 20.04 Focal Fossa x86_64' --key-name {key_name} --flavor '1C-2GB-50GB' --network {tag}_network --security-group {tag}_secgroup {name}"
            result = subprocess.run(create_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            if result.returncode == 0:
                existing_nodes.append(name)
                print(f"{get_current_time()}: Successfully created {name}.")
                time.sleep(10)
            else:
                print(f"{get_current_time()}: Failed to create {name}. Error: {result.stderr}")

        print(f"{get_current_time()}: Verifying if all servers are running...")

        all_running = all(check_server_status(node) for node in existing_nodes)
        if all_running:
            print(f"{get_current_time()}: All nodes are running.")
        else:
            non_running = [node for node in existing_nodes if not check_server_status(node)]
            print(f"{get_current_time()}: The following nodes are not running: {', '.join(non_running)}.")

            for node in non_running:
                print(f"{get_current_time()}: Attempting to start {node}...")
                result = subprocess.run(f"openstack server start {node}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if result.returncode == 0:
                    print(f"{get_current_time()}: Successfully started {node}.")
                else:
                    print(f"{get_current_time()}: Failed to start {node}. Error: {result.stderr}")

            print(f"{get_current_time()}: Waiting for 30 seconds...")
            time.sleep(30)

        bastion_name = f"{tag}_bastion"
        proxy1_name = f"{tag}_proxy1"
        proxy2_name = f"{tag}_proxy2"

        for server_name in [bastion_name, proxy1_name, proxy2_name]:
            if not check_server_status(server_name):
                result = subprocess.run(f"openstack server start {server_name}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if result.returncode == 0:
                    print(f"{get_current_time()}: Successfully started {server_name}.")
                else:
                    print(f"{get_current_time()}: Failed to start {server_name}. Error: {result.stderr}")

        # Collect IPs for HAProxy and Ansible configuration
        haproxy1_ip = get_fixed_ip(proxy1_name)
        haproxy2_ip = get_fixed_ip(proxy2_name)
        bastion_ip = get_fixed_ip(bastion_name)
        dev_ips = {name: get_fixed_ip(name) for name in server_names if name in existing_nodes}

        with open('haproxy.cfg', 'w') as file:
            file.write(f"server haproxy1 {haproxy1_ip}:6443 check\n")
            file.write(f"server haproxy2 {haproxy2_ip}:6443 check\n")

        with open('hosts', 'w') as file:
            file.write(f"[bastion]\n")
            file.write(f"{bastion_name} ansible_host={bastion_ip} ansible_ssh_user=ubuntu ansible_ssh_private_key_file={ssh_key}\n")
            file.write(f"[main_proxy]\n")
            file.write(f"{proxy1_name} ansible_host={haproxy1_ip} ansible_ssh_user=ubuntu ansible_ssh_private_key_file={ssh_key}\n")
            file.write(f"[backup_proxy]\n")
            file.write(f"{proxy2_name} ansible_host={haproxy2_ip} ansible_ssh_user=ubuntu ansible_ssh_private_key_file={ssh_key}\n")
            file.write(f"[dev]\n")
            for dev_name, dev_ip in dev_ips.items():
                if dev_ip:  # Ensure the IP was successfully retrieved
                    file.write(f"{dev_name} ansible_host={dev_ip} ansible_ssh_user=ubuntu ansible_ssh_private_key_file={ssh_key}\n")

        execute_ansible_tasks()

