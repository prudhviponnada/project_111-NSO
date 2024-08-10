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
    instances = list(conn.compute.servers(name=name))
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
        ports = list(conn.network.ports())
        for port in ports:
            if sec_group.id in port.security_group_ids:
                conn.network.delete_port(port.id)
                print(f"Deleted port {port.id} associated with security group {sec_group_name}")

        max_retries = 5
        for attempt in range(max_retries):
            try:
                conn.network.delete_security_group(sec_group)
                print(f"Deleted security group {sec_group_name}")
                break
            except openstack.exceptions.ConflictException:
                print(f"Attempt {attempt + 1}: Security group {sec_group_name} in use, retrying...")
                time.sleep(5)
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
                if any(ip['subnet_id'] == subnet.id for ip in port.fixed_ips):
                    if port.device_owner.startswith("network:router_interface") or port.device_owner == "network:ha_router_replicated_interface":
                        router_id = port.device_id
                        conn.network.remove_interface_from_router(router_id, subnet_id=subnet.id)
                        print(f"Removed interface {port.id} from router {router_id}")
                    conn.network.delete_port(port.id)
                    print(f"Deleted port {port.id} associated with subnet {subnet.id}")
            conn.network.delete_subnet(subnet.id)
            print(f"Deleted subnet {subnet.name}")
        conn.network.delete_network(network.id)
        print(f"Deleted network {network_name}")
    else:
        print(f"Network {network_name} not found")

def count_servers(conn, tag):
    servers = list(conn.compute.servers())
    count = sum(1 for server in servers if server.name.startswith(tag))
    return count

def delete_tagged_instances(conn, tag):
    server_count = count_servers(conn, tag)
    for i in range(1, server_count - 2):
        server_name = f"{tag}_node{i}"
        delete_instance(conn, server_name)

def delete_ports_associated_with_router(conn, router_id):
    ports = list(conn.network.ports(device_id=router_id))
    for port in ports:
        conn.network.delete_port(port.id)
        print(f"Deleted port {port.id} associated with router {router_id}")

def detach_subnets_from_router(conn, router_id):
    ports = list(conn.network.ports(device_id=router_id))
    for port in ports:
        if port.device_owner.startswith("network:router_interface") or port.device_owner == "network:ha_router_replicated_interface":
            subnet_id = port.fixed_ips[0]['subnet_id']
            conn.network.remove_interface_from_router(router_id, subnet_id=subnet_id)
            print(f"Detached subnet {subnet_id} from router {router_id}")

def remove_external_gateway(conn, router_id):
    router = conn.network.find_router(router_id)
    if router and router.external_gateway_info:
        try:
            conn.network.remove_router_gateway(router_id)
            print(f"Removed external gateway from router {router_id}")
        except Exception as e:
            print(f"Failed to remove external gateway from router {router_id}: {e}")

def delete_router(conn, router_name):
    router = conn.network.find_router(router_name)
    if router:
        router_id = router.id

        detach_subnets_from_router(conn, router_id)
        delete_ports_associated_with_router(conn, router_id)
        remove_external_gateway(conn, router_id)

        try:
            conn.network.delete_router(router_id)
            print(f"Deleted router {router_name}")
        except Exception as e:
            print(f"Failed to delete router {router_name}: {e}")
    else:
        print(f"Router {router_name} not found")

def delete_floating_ips(conn):
    floating_ips = list(conn.network.ips())
    for ip in floating_ips:
        if ip.fixed_ip_address is None:
            try:
                conn.network.delete_ip(ip.id)
                print(f"Deleted floating IP {ip.floating_ip_address}")
            except Exception as e:
                print(f"Failed to delete floating IP {ip.floating_ip_address}: {e}")

def main(openrc, tag, ssh_key):
    load_openrc(openrc)
    conn = openstack.connect()

    delete_tagged_instances(conn, tag)
    delete_instance(conn, tag + "_bastion")
    delete_instance(conn, tag + "_proxy1")
    delete_instance(conn, tag + "_proxy2")

    delete_keypair(conn, tag + "_key")
    delete_security_group(conn, tag + "_secgroup")
    delete_network(conn, tag + "_network")

    routers = list(conn.network.routers(name=tag + "_"))
    for router in routers:
        delete_router(conn, router.name)

    delete_floating_ips(conn)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: cleanup.py <openrc> <tag> <ssh_key>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2], sys.argv[3])
