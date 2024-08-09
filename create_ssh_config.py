import os
import json
import sys

def create_ssh_config_file(tag, instances):
    print(f"Tag: {tag}")
    print(f"Instances: {instances}")

    ssh_config_path = os.path.expanduser(f"~/.ssh/{tag}_config")
    with open(ssh_config_path, "w") as file:
        file.write("# SSH Configurations\n")
        file.write("Host *\n")
        file.write(f"\tUser ubuntu\n")
        file.write(f"\tIdentityFile ~/.ssh/{tag}_private.pem\n")
        file.write(f"\tStrictHostKeyChecking no\n")
        file.write(f"\tPasswordAuthentication no\n")
        file.write(f"\tServerAliveInterval 60\n\n")

        # Additional settings for all hosts
        file.write(f"\tForwardAgent yes\n")
        file.write(f"\tControlMaster auto\n")
        file.write(f"\tControlPath ~/.ssh/ansible-%r@%h:%p\n")
        file.write(f"\tControlPersist yes\n\n")

        # Loop through the instances and configure each one
        for name, details in instances.items():
            if details["floating_ip"]:
                file.write(f"Host {tag}_{name}\n")
                file.write(f"\tHostName {details['floating_ip']}\n")
                if name.startswith("proxy"):
                    file.write(f"\tProxyCommand ssh -W %h:%p {tag}_bastion\n")
            else:
                file.write(f"Host {tag}_{name}\n")
                file.write(f"\tHostName {details['internal_ip']}\n")
                file.write(f"\tProxyCommand ssh -W %h:%p {tag}_bastion\n")
            file.write("\n")

    print(f"SSH config file generated: {ssh_config_path}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python create_ssh_config.py <tag> <instances>")
        sys.exit(1)
    
    tag = sys.argv[1]
    instances = {}
    
    # Assuming instances is passed as a JSON string for simplicity
    try:
        instances = json.loads(sys.argv[2])
    except json.JSONDecodeError:
        print("Invalid instances JSON format")
        sys.exit(1)

    create_ssh_config_file(tag, instances)
