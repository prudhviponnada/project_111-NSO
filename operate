#!/usr/bin/python3
import os
import sys
import subprocess
import re
import time
import datetime
import json
import logging
from python_files.create_ssh_config import create_ssh_config_file, write_hosts
from python_files.ansible_playbook import run_playbook, ansible_ping

def get_current_time():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def check_server_status(server_name):
    result = subprocess.run(f"openstack server show {server_name}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return "ACTIVE" in result.stdout

def validate_keypair(key_name):
    result = subprocess.run("openstack keypair list -f value -c Name", shell=True, stdout=subprocess.PIPE, text=True)
    keypairs = result.stdout.splitlines()
    return key_name in keypairs

def get_fixed_ip(server_name):
    try:
        command = f"openstack server show {server_name} -c addresses -f json"
        output = subprocess.check_output(command, shell=True).decode()
        addresses = json.loads(output)["addresses"]
        internal_ip = addresses.split(",")[0].split("=")[1].strip() if "=" in addresses else addresses
        return internal_ip
    except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError, IndexError) as e:
        print(f"{get_current_time()}: Failed to get IP for {server_name}. Error: {str(e)}")
        return None

def get_keepalived_ip():
    try:
        command = f"openstack port show my-keepalived-port -c fixed_ips -f json"
        output = subprocess.check_output(command, shell=True).decode()
        port_data = json.loads(output)
        fixed_ips = port_data.get("fixed_ips", [])
        if fixed_ips:
            return fixed_ips[0]["ip_address"]
        else:
            print(f"{get_current_time()}: No fixed IP found for my-keepalived-port.")
            sys.exit(1)
    except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError, IndexError) as e:
        print(f"{get_current_time()}: Failed to get keepalived port IP. Error: {str(e)}")
        sys.exit(1)

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
server_names = [f"{tag}_dev{i+1}" for i in range(10)]

while True:
    with open('server.conf', 'r') as file:
        config_lines = file.readlines()

    num_dev = None
    for line in config_lines:
        if "num_dev =" in line:
            match = re.search(r'num_dev = (\d+)', line)
            if match:
                num_devs = int(match.group(1))
            break

    if num_devs is None:
        print(f"{get_current_time()}: Could not determine the number of required dev from server.conf.")
        sys.exit(1)

    print(f"{get_current_time()}: Server configuration requires {num_devs} dev.")

    result = subprocess.run("openstack server list -c Name -f value", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    existing_dev = re.findall(rf"^{tag}_dev\d+", result.stdout, re.MULTILINE)
    all_servers = result.stdout.splitlines()  # Get all servers for bastion and proxies
    print(f"{get_current_time()}: Found {len(existing_dev)} existing dev. Sleeping for 30 seconds...")
    time.sleep(30)

    if len(existing_dev) == num_devs:
        time.sleep(30)
    elif len(existing_dev) > num_devs:
        excess_dev = len(existing_dev) - num_devs
        print(f"{get_current_time()}: There are/is {excess_dev} excess dev.")

        existing_dev.sort(reverse=True)
        removed_count = 0

        for dev in existing_dev:
            if removed_count >= excess_dev:
                break

            result = subprocess.run(f"openstack server delete {dev}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            time.sleep(20)

            if result.returncode == 0:
                removed_count += 1
                print(f"{get_current_time()}: Successfully deleted {dev}.")
            else:
                print(f"{get_current_time()}: Failed to delete {dev}. Error: {result.stderr}")
    else:
        missing_dev = num_devs - len(existing_dev)
        missing_server_names = [name for name in server_names if name not in existing_dev]

        for name, _ in zip(missing_server_names, range(missing_dev)):
            print(f"{get_current_time()}: Creating missing dev: {name}.")
            create_command = f"openstack server create --image 'Ubuntu 20.04 Focal Fossa x86_64' --key-name {key_name} --flavor '1C-2GB-50GB' --network {tag}_network --security-group {tag}_secgroup {name}"
            result = subprocess.run(create_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            if result.returncode == 0:
                existing_dev.append(name)
                print(f"{get_current_time()}: Successfully created {name}.")
                time.sleep(10)
            else:
                print(f"{get_current_time()}: Failed to create {name}. Error: {result.stderr}")

        print(f"{get_current_time()}: Verifying if all servers are running...")

        all_running = all(check_server_status(dev) for dev in existing_dev)
        if all_running:
            print(f"{get_current_time()}: All dev are running.")
        else:
            non_running = [dev for dev in existing_dev if not check_server_status(dev)]
            print(f"{get_current_time()}: The following dev are not running: {', '.join(non_running)}.")

            for dev in non_running:
                print(f"{get_current_time()}: Attempting to start {dev}...")
                result = subprocess.run(f"openstack server start {dev}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if result.returncode == 0:
                    print(f"{get_current_time()}: Successfully started {dev}.")
                else:
                    print(f"{get_current_time()}: Failed to start {dev}. Error: {result.stderr}")

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
        dev_ips = {name: get_fixed_ip(name) for name in server_names if name in existing_dev}

        # Load existing instances.json if it exists
        instances_file_path = os.path.join(os.getcwd(), "instances.json")
        instance_details = {}
        if os.path.exists(instances_file_path):
            with open(instances_file_path, 'r') as instances_file:
                instance_details = json.load(instances_file)

        # Update instance_details with only active servers
        instance_details = {
            name: details for name, details in instance_details.items()
            if name in all_servers or name in [bastion_name, proxy1_name, proxy2_name] + existing_dev
        }

        instance_details.update({
            bastion_name: {"internal_ip": bastion_ip, "floating_ip": instance_details.get(bastion_name, {}).get("floating_ip")},
            proxy1_name: {"internal_ip": haproxy1_ip, "floating_ip": None},
            proxy2_name: {"internal_ip": haproxy2_ip, "floating_ip": None},
        })
        for dev_name, dev_ip in dev_ips.items():
            if dev_ip:
                instance_details[dev_name] = {"internal_ip": dev_ip, "floating_ip": None}

        # If bastion's floating_ip is still None, query OpenStack
        if instance_details.get(bastion_name, {}).get("floating_ip") is None:
            try:
                command = f"openstack server show {bastion_name} -c addresses -f json"
                output = subprocess.check_output(command, shell=True).decode()
                addresses = json.loads(output)["addresses"]
                if "," in addresses:
                    floating_ip = addresses.split(",")[1].strip()
                    instance_details[bastion_name]["floating_ip"] = floating_ip
                else:
                    print(f"{get_current_time()}: No floating IP found for {bastion_name}.")
                    sys.exit(1)
            except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError, IndexError) as e:
                print(f"{get_current_time()}: Failed to get floating IP for {bastion_name}. Error: {str(e)}")
                sys.exit(1)

        # Filter out instances with None IPs
        instance_details = {name: details for name, details in instance_details.items() if details["internal_ip"]}

        # Write updated instance_details to instances.json
        with open(instances_file_path, 'w') as instances_file:
            json.dump(instance_details, instances_file, indent=4)
        print(f"{get_current_time()}: Instances details written to {instances_file_path}")

        # Write HAProxy configuration with correct ports
        with open('haproxy.cfg', 'w') as file:
            file.write("frontend service_front\n")
            file.write("    bind *:5000\n")
            file.write("    default_backend service_back\n")
            file.write("frontend snmp_front\n")
            file.write("    bind *:6000 proto udp\n")
            file.write("    default_backend snmp_back\n")
            file.write("backend service_back\n")
            file.write(f"    server haproxy1 {haproxy1_ip}:5000 check\n")
            file.write(f"    server haproxy2 {haproxy2_ip}:5000 check\n")
            file.write("backend snmp_back\n")
            file.write(f"    server haproxy1 {haproxy1_ip}:6000 check proto udp\n")
            file.write(f"    server haproxy2 {haproxy2_ip}:6000 check proto udp\n")

        # Create Ansible hosts file using write_hosts
        instances = {
            name: {
                "internal_ip": details["internal_ip"],
                "floating_ip": details["floating_ip"],
                "name": name
            } for name, details in instance_details.items()
        }
        print(f"{get_current_time()}: Creating Ansible hosts file.")
        write_hosts(tag, instances)

        # Create SSH configuration file
        private_key_path = ssh_key.rsplit('.pub', 1)[0] if ssh_key.endswith('.pub') else ssh_key
        print(f"{get_current_time()}: Creating SSH configuration file.")
        create_ssh_config_file(tag, instances_file_path, private_key_path)

        logging.info("ping all hosts")
        if not ansible_ping(tag):
            sys.exit(1)

        # Execute Ansible playbook with keepalived virtual IP
        virtual_ip = get_keepalived_ip()
        logging.info("Executing Ansible playbook.")
        run_playbook(tag, virtual_ip=virtual_ip)
