import sys

def create_hosts_file(tag, num_dev_servers, output_file):
    with open(output_file, 'w') as f:
        # Write Bastion host section
        f.write('[Bastionhost]\n')
        bastion_hostname = f'{tag}_bastion'
        f.write(f'{bastion_hostname}\n\n')

        # Write HAProxy section
        f.write('[haproxy]\n')
        haproxy_hostname = f'{tag}_haproxy'
        backup_haproxy_hostname = f'{tag}_backuphaproxy'
        f.write(f'{haproxy_hostname}\n')
        f.write(f'{backup_haproxy_hostname}\n\n')

        # Write Dev servers section
        f.write('[dev servers]\n')
        for i in range(1, num_dev_servers - 2):
            dev_hostname = f'{tag}_node{i}'
            f.write(f'{dev_hostname}\n')
        f.write('\n')

        # Write variables section
        f.write('[all:vars]\n')
        f.write('ansible_user=ubuntu\n')

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python hosts_file.py <tag> <num_dev_servers> <output_file>")
        sys.exit(1)

    print(f"Arguments received: {sys.argv}")

    tag = sys.argv[1]
    try:
        num_dev_servers = int(sys.argv[2])
    except ValueError:
        print(f"Error: '{sys.argv[2]}' is not a valid number for the number of dev servers.")
        sys.exit(1)
    output_file = sys.argv[3]

    create_hosts_file(tag, num_dev_servers, output_file)
