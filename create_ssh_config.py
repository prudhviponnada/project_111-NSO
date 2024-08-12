import os
import json
import sys

def write_hosts(tag, instances):
    with open('./hosts', 'w') as f:
        f.write('[bastion]\n')
        hostname = tag + '_bastion'
        f.write(f'{hostname}\n')
        f.write('[HAproxy]\n')
        hostname = tag + '_proxy1'
        f.write(f'{hostname}\n')
        hostname = tag + '_proxy2'
        f.write(f'{hostname}\n')
        f.write('\n')
        f.write('[primary_proxy]\n')
        hostname = tag + '_proxy1'
        f.write(f'{hostname}\n')
        f.write('[backup_proxy]\n')
        hostname = tag + '_proxy2'
        f.write(f'{hostname}\n')
        f.write('\n')
        
        f.write('[dev]\n')
        for _, details in instances.items():
            if details['name'] not in [f"{tag}_bastion", f"{tag}_proxy1", f"{tag}_proxy2"]:
                f.write(f"{details['name']}\n")
        f.write('\n')
        f.write('[all:vars]\n')
        f.write('ansible_user=ubuntu\n')


def create_ssh_config_file(tag, instances_file_path, private_key_path):
    # Load instances data from the file
    with open(instances_file_path, 'r') as file:
        instances = json.load(file)

    print(f"Tag: {tag}")
    print(f"Instances: {instances}")

    ssh_config_path = os.path.expanduser(f"./{tag}_config")
    with open(ssh_config_path, "w") as file:
        file.write("# SSH Configurations\n")
        file.write("Host *\n")
        file.write(f"\tUser ubuntu\n")
        file.write(f"\tIdentityFile {private_key_path}\n")
        file.write(f"\tStrictHostKeyChecking no\n")
        file.write(f"\tPasswordAuthentication no\n")
        # Additional settings for all hosts
        file.write(f"\tForwardAgent yes\n")

        # Loop through the instances and configure each one
        for name, details in instances.items():
            
            if name == "bastion":
                file.write(f"Host {tag}_{name}\n")
                file.write(f"\tHostName {details['floating_ip']}\n")
            
                
            else:
                file.write(f"Host {tag}_{name}\n")
                file.write(f"\tHostName {details['internal_ip']}\n")
                file.write(f"\tproxyjump {tag}_bastion\n")
            file.write("\n")

    print(f"SSH config file generated: {ssh_config_path}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python create_ssh_config.py <tag> <instances-file>")
        sys.exit(1)
    
    tag = sys.argv[1]
    instances_file_path = sys.argv[2]

    create_ssh_config_file(tag, instances_file_path, sys.argv[3])
