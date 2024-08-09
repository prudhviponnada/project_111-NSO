# import openstack
# import sys
# import os
# import subprocess
# import time

# def load_openrc(openrc):
#     command = f"bash -c 'source {openrc} && env'"
#     proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
#     for line in proc.stdout:
#         (key, _, value) = line.decode("utf-8").partition("=")
#         os.environ[key] = value.strip()
#     proc.communicate()

# def delete_instance(conn, name):
#     instances = list(conn.compute.servers(details=False, name=name))
#     if not instances:
#         print(f"Instance {name} not found")
#     else:
#         for instance in instances:
#             conn.compute.delete_server(instance)
#             conn.compute.wait_for_delete(instance)
#             print(f"Deleted instance {instance.name}")

# def delete_keypair(conn, key_name):
#     keypair = conn.compute.find_keypair(key_name)
#     if keypair:
#         conn.compute.delete_keypair(keypair)
#         print(f"Deleted keypair {key_name}")
#     else:
#         print(f"Keypair {key_name} not found")

# def delete_security_group(conn, sec_group_name):
#     sec_group = conn.network.find_security_group(sec_group_name)
#     if sec_group:
#         # List and delete all ports associated with the security group
#         ports = list(conn.network.ports())
#         for port in ports:
#             if any(sg['id'] == sec_group.id for sg in port.security_group_ids):
#                 conn.network.delete_port(port)
#                 print(f"Deleted port {port.id} associated with security group {sec_group_name}")

#         # Retry mechanism for deleting the security group
#         max_retries = 5
#         for attempt in range(max_retries):
#             try:
#                 conn.network.delete_security_group(sec_group)
#                 print(f"Deleted security group {sec_group_name}")
#                 break
#             except openstack.exceptions.ConflictException as e:
#                 print(f"Attempt {attempt + 1}: Security group {sec_group_name} in use, retrying...")
#                 time.sleep(5)  # Wait for 5 seconds before retrying
#         else:
#             print(f"Failed to delete security group {sec_group_name} after {max_retries} attempts")
#     else:
#         print(f"Security group {sec_group_name} not found")

# def delete_network(conn, network_name):
#     network = conn.network.find_network(network_name)
#     if network:
#         subnets = list(conn.network.subnets(network_id=network.id))
#         for subnet in subnets:
#             ports = list(conn.network.ports())
#             for port in ports:
#                 if subnet.id in [ip['subnet_id'] for ip in port.fixed_ips]:
#                     if port.device_owner.startswith("network:router_interface"):
#                         router_id = port.device_id
#                         conn.network.remove_interface_from_router(router_id, subnet_id=subnet.id)
#                         print(f"Removed router interface {router_id} from subnet {subnet.id}")
#                     elif port.device_owner == "network:ha_router_replicated_interface":
#                         router_id = port.device_id
#                         conn.network.remove_interface_from_router(router_id, subnet_id=subnet.id)
#                         print(f"Removed HA router interface {router_id} from subnet {subnet.id}")
#                     conn.network.delete_port(port)
#                     print(f"Deleted port {port.id}")
#             conn.network.delete_subnet(subnet)
#             print(f"Deleted subnet {subnet.name}")
#         conn.network.delete_network(network)
#         print(f"Deleted network {network_name}")
#     else:
#         print(f"Network {network_name} not found")

# def count_servers_in_network(conn, network_name):
#     servers = list(conn.compute.servers(details=True))
#     network = conn.network.find_network(network_name)
#     if not network:
#         print(f"Network {network_name} not found")
#         return 0

#     count = 0
#     for server in servers:
#         for interface in server.addresses.values():
#             for addr in interface:
#                 if addr.get('network_id') == network.id:
#                     count += 1
#                     break
#     return count

# def main(openrc, tag, ssh_key):
#     load_openrc(openrc)
#     conn = openstack.connect()

#     network_name = tag + "_network"
#     server_count = count_servers_in_network(conn, network_name)
#     print(f"Number of servers in network {network_name}: {server_count}")

#     delete_instance(conn, tag + "_bastion")
#     delete_instance(conn, tag + "_proxy1")
#     delete_instance(conn, tag + "_proxy2")

#     # Adjust the range for deleting service node instances
#     for i in range(1, max(1, server_count - 3 + 1)):  # Ensure the range is at least 1
#         delete_instance(conn, f"{tag}_node{i}")

#     delete_keypair(conn, tag + "_key")
#     delete_security_group(conn, tag + "_secgroup")
#     delete_network(conn, network_name)

# if __name__ == "__main__":
#     if len(sys.argv) != 4:
#         print("Usage: cleanup.py <openrc> <tag> <ssh_key>")
#         sys.exit(1)
#     main(sys.argv[1], sys.argv[2], sys.argv[3])



import openstack
import sys
import os
import subprocess
import time

def load_openrc(openrc):
    command = f"bash -c 'source {openrc} && env'"
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    for line in proc.stdout:
        (key, _, value) = line.decode("utf-8").partition("=")
        os.environ[key] = value.strip()
    proc.communicate()

def delete_instance(conn, name):
    instances = list(conn.compute.servers(details=False, name=name))
    if not instances:
        print(f"Instance {name} not found")
    else:
        for instance in instances:
            conn.compute.delete_server(instance)
            conn.compute.wait_for_delete(instance)
            print(f"Deleted instance {instance.name}")

def delete_keypair(conn, key_name):
    keypair = conn.compute.find_keypair(key_name)
    if keypair:
        conn.compute.delete_keypair(keypair)
        print(f"Deleted keypair {key_name}")
    else:
        print(f"Keypair {key_name} not found")

def delete_security_group(conn, sec_group_name):
    sec_group = conn.network.find_security_group(sec_group_name)
    if sec_group:
        # List and delete all ports associated with the security group
        ports = list(conn.network.ports())
        for port in ports:
            # Check the structure of security_group_ids
            # print(f"Security Group IDs for port {port.id}: {port.security_group_ids}")
            
            # Assuming security_group_ids is a list of strings (ids)
            if sec_group.id in port.security_group_ids:
                conn.network.delete_port(port)
                # print(f"Deleted port {port.id} associated with security group {sec_group_name}")

        # Retry mechanism for deleting the security group
        max_retries = 5
        for attempt in range(max_retries):
            try:
                conn.network.delete_security_group(sec_group)
                print(f"Deleted security group {sec_group_name}")
                break
            except openstack.exceptions.ConflictException as e:
                print(f"Attempt {attempt + 1}: Security group {sec_group_name} in use, retrying...")
                time.sleep(5)  # Wait for 5 seconds before retrying
        else:
            print(f"Failed to delete security group {sec_group_name} after {max_retries} attempts")
    else:
        print(f"Security group {sec_group_name} not found")

def delete_network(conn, network_name):
    network = conn.network.find_network(network_name)
    if network:
        subnets = list(conn.network.subnets(network_id=network.id))
        for subnet in subnets:
            ports = list(conn.network.ports())
            for port in ports:
                if subnet.id in [ip['subnet_id'] for ip in port.fixed_ips]:
                    if port.device_owner.startswith("network:router_interface"):
                        router_id = port.device_id
                        conn.network.remove_interface_from_router(router_id, subnet_id=subnet.id)
                        print(f"Removed router interface {router_id} from subnet {subnet.id}")
                    elif port.device_owner == "network:ha_router_replicated_interface":
                        router_id = port.device_id
                        conn.network.remove_interface_from_router(router_id, subnet_id=subnet.id)
                        print(f"Removed HA router interface {router_id} from subnet {subnet.id}")
                    conn.network.delete_port(port)
                    print(f"Deleted port {port.id}")
            conn.network.delete_subnet(subnet)
            print(f"Deleted subnet {subnet.name}")
        conn.network.delete_network(network)
        print(f"Deleted network {network_name}")
    else:
        print(f"Network {network_name} not found")

# def main(openrc, tag, ssh_key):
#     load_openrc(openrc)
#     conn = openstack.connect()

#     delete_instance(conn, tag + "_bastion")
#     delete_instance(conn, tag + "_proxy1")
#     delete_instance(conn, tag + "_proxy2")
#     for i in range(1, 10):
#         delete_instance(conn, f"{tag}_node{i}")

#     delete_keypair(conn, tag + "_key")
#     delete_security_group(conn, tag + "_secgroup")
#     delete_network(conn, tag + "_network")

# if __name__ == "__main__":
#     if len(sys.argv) != 4:
#         print("Usage: cleanup.py <openrc> <tag> <ssh_key>")
#         sys.exit(1)
#     main(sys.argv[1], sys.argv[2], sys.argv[3])

def delete_instances_with_tag(conn, tag):
    # List all instances that match the tag
    instances = list(conn.compute.servers(details=False, name=tag + "_"))
    
    # Count the number of instances
    instance_count = len(instances)
    
    if instance_count == 0:
        print(f"No instances found with the tag '{tag}'")
    else:
        for instance in instances:
            conn.compute.delete_server(instance)
            conn.compute.wait_for_delete(instance)
            print(f"Deleted instance {instance.name}")
    
    return instance_count

def main(openrc, tag, ssh_key):
    load_openrc(openrc)
    conn = openstack.connect()

    # Delete instances and get the count
    bastion_count = delete_instances_with_tag(conn, tag + "_bastion")
    proxy1_count = delete_instances_with_tag(conn, tag + "_proxy1")
    proxy2_count = delete_instances_with_tag(conn, tag + "_proxy2")
    node_count = 0

    for i in range(1, 10):
        node_count += delete_instances_with_tag(conn, f"{tag}_node{i}")
    
    total_deleted = bastion_count + proxy1_count + proxy2_count + node_count
    print(f"Total number of instances deleted: {total_deleted}")

    delete_keypair(conn, tag + "_key")
    delete_security_group(conn, tag + "_secgroup")
    delete_network(conn, tag + "_network")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: cleanup.py <openrc> <tag> <ssh_key>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2], sys.argv[3])
