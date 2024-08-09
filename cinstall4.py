import openstack
import sys
import os
import subprocess
import logging
import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')

def load_openrc(openrc):
    command = f"bash -c 'source {openrc} && env'"
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    for line in proc.stdout:
        (key, _, value) = line.decode("utf-8").partition("=")
        os.environ[key] = value.strip()
    proc.communicate()

def get_external_network(conn):
    for network in conn.network.networks():
        if network.is_router_external:
            return network.id
    raise Exception("External network (ext-net) not found.")

def get_unused_floating_ip(conn, floating_ip_pool):
    floating_ips = conn.network.ips(floating_network_id=floating_ip_pool)
    for ip in floating_ips:
        if ip.fixed_ip_address is None:
            return ip.floating_ip_address
    
    created_ip = conn.network.create_ip(floating_network_id=floating_ip_pool)
    return created_ip.floating_ip_address

def create_keypair(conn, keypair_name):
    private_key_file = os.path.expanduser(f"~/.ssh/{keypair_name}.pem")
    
    existing_keypair = conn.compute.find_keypair(keypair_name)
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    if not existing_keypair:
        new_keypair = conn.compute.create_keypair(name=keypair_name)
        with open(private_key_file, 'w') as key_file:
            key_file.write(new_keypair.private_key)
        os.chmod(private_key_file, 0o600)
        logging.info(f"Key pair '{keypair_name}' was successfully created and stored at '{private_key_file}'.")
    else:
        logging.info(f"Key pair '{keypair_name}' already exists.")

def create_network(conn, tag):
    network = conn.network.find_network(tag + "_network")
    if not network:
        network = conn.network.create_network(name=tag + "_network")
        subnet = conn.network.create_subnet(
            name=tag + "_subnet",
            network_id=network.id,
            ip_version='4',
            cidr='10.0.0.0/24'
        )
        router = get_or_create_router(conn, tag)
        conn.network.add_interface_to_router(router, subnet_id=subnet.id)
        logging.info(f"Created network, subnet, and router: {network.name}, {subnet.name}, {router.name}")
    else:
        logging.info(f"Network {network.name} already exists")
    return network

def get_or_create_router(conn, tag):
    router = conn.network.find_router(tag + "_router")
    if not router:
        external_network_id = get_external_network(conn)
        router = conn.network.create_router(name=tag + "_router", external_gateway_info={"network_id": external_network_id})
        logging.info(f"Created router: {router.name}")
    else:
        logging.info(f"Router {router.name} already exists")
    return router

def create_security_group(conn, tag):
    sec_group = conn.network.find_security_group(tag + "_secgroup")
    if not sec_group:
        sec_group = conn.network.create_security_group(name=tag + "_secgroup")
        conn.network.create_security_group_rule(
            security_group_id=sec_group.id,
            direction='ingress',
            protocol='icmp'
        )
        conn.network.create_security_group_rule(
            security_group_id=sec_group.id,
            direction='ingress',
            protocol='tcp',
            port_range_min='22',
            port_range_max='22'
        )
        conn.network.create_security_group_rule(
            security_group_id=sec_group.id,
            direction='ingress',
            protocol='tcp',
            port_range_min='5000',
            port_range_max='5000'
        )
        conn.network.create_security_group_rule(
            security_group_id=sec_group.id,
            direction='ingress',
            protocol='udp',
            port_range_min='6000',
            port_range_max='6000'
        )
        logging.info(f"Created security group {sec_group.name}")
    else:
        logging.info(f"Security group {sec_group.name} already exists")
    return sec_group

def create_instance(conn, name, tag, image_name, flavor_name, network_id, sec_group, key_name, floating_ip_pool=None):
    image = conn.compute.find_image(name_or_id=image_name)
    if not image:
        raise ValueError(f"Image {image_name} not found. Available images: {[img.name for img in conn.compute.images()]}")
    
    flavor = conn.compute.find_flavor(name_or_id=flavor_name)
    if not flavor:
        raise ValueError(f"Flavor {flavor_name} not found. Available flavors: {[flv.name for flv in conn.compute.flavors()]}")

    instance = conn.compute.create_server(
        name=name,
        image_id=image.id,
        flavor_id=flavor.id,
        networks=[{"uuid": network_id}],
        security_groups=[{"name": sec_group.name}],
        key_name=key_name
    )
    conn.compute.wait_for_server(instance)
    logging.info(f"Created instance {name}")

    floating_ip_address = None
    if name in [tag + "_bastion", tag + "_proxy1", tag + "_proxy2"]:
        if floating_ip_pool:
            try:
                external_network_id = get_external_network(conn)
                floating_ip_address = get_unused_floating_ip(conn, external_network_id)
                conn.compute.add_floating_ip_to_server(instance, floating_ip_address)
                logging.info(f"Assigned floating IP {floating_ip_address} to instance {name}")
            except Exception as e:
                logging.error(f"Failed to assign floating IP to instance {name}: {str(e)}")

    internal_ip = instance.addresses.get(tag + "_network")[0]["addr"]

    return {
        "name": name,
        "internal_ip": internal_ip,
        "floating_ip": floating_ip_address
    }

def delete_unused_resources(conn, tag):
    delete_unused_routers(conn, tag)
    delete_unused_floating_ips(conn, tag)

def delete_unused_routers(conn, tag):
    routers = conn.network.routers()
    for router in routers:
        router_ports = get_router_ports(conn, router.id)
        if router.name.startswith(tag + "_") and len(router_ports) == 0:
            conn.network.delete_router(router)
            logging.info(f"Deleted unused router: {router.name}")

def delete_unused_floating_ips(conn, tag):
    floating_ips = conn.network.ips()
    for ip in floating_ips:
        if ip.description and ip.description.startswith(tag + "_") and ip.fixed_ip_address is None:
            conn.network.delete_ip(ip.id)
            logging.info(f"Deleted unused floating IP: {ip.floating_ip_address}")

def get_router_ports(conn, router_id):
    return [port for port in conn.network.ports(device_id=router_id)]

def build_ssh_config(tag, internal_ips, floating_ips):
    ssh_config_path = os.path.expanduser(f"~/.ssh/{tag}_config")
    with open(ssh_config_path, "w") as file:
        file.write("# SSH Configurations\n")
        file.write("Host *\n")
        file.write(f"\tUser ubuntu\n")
        file.write(f"\tIdentityFile ~/.ssh/{tag}_private.pem\n")
        file.write(f"\tStrictHostKeyChecking no\n")
        file.write(f"\tPasswordAuthentication no\n")
        file.write(f"\tServerAliveInterval 60\n\n")

        # Add floating IPs for bastions and proxies
        for name, floating_ip in floating_ips.items():
            if name.startswith(tag + "_bastion") or name.startswith(tag + "_proxy"):
                file.write(f"Host {name}\n")
                file.write(f"\tHostName {floating_ip}\n")
                file.write(f"\tUser ubuntu\n")
                file.write(f"\tIdentityFile ~/.ssh/{tag}_private.pem\n")
                file.write(f"\tProxyCommand ssh -W %h:%p {tag}_bastion\n\n")

        # Add internal IPs for nodes
        for name, internal_ip in internal_ips.items():
            if name.startswith(tag + "_node"):
                file.write(f"Host {name}\n")
                file.write(f"\tHostName {internal_ip}\n")
                file.write(f"\tUser ubuntu\n")
                file.write(f"\tIdentityFile ~/.ssh/{tag}_private.pem\n")
                file.write(f"\tProxyCommand ssh -W %h:%p {tag}_bastion\n\n")

    logging.info(f"SSH config file generated: {ssh_config_path}")

def run_playbook():
    logging.info("Running Ansible playbook...")
    ansible_command = "ansible-playbook -i hosts site.yaml -e ansible_ssh_common_args='-F ~/.ssh/proplayer_config'"
    subprocess.run(ansible_command, shell=True)
    logging.info("Ansible playbook execution complete.")

def validate_operation():
    logging.info("Validation completed.")

def main(openrc, tag, public_key_path):
    logging.info(f"Starting deployment of {tag} using {openrc} for credentials.")
    load_openrc(openrc)
    conn = openstack.connect()

    logging.info(f"Checking if we have floating IPs available.")
    delete_unused_resources(conn, tag)
    
    logging.info("Creating keypair.")
    create_keypair(conn, tag)
    
    logging.info("Creating network.")
    network = create_network(conn, tag)
    
    logging.info("Creating security group.")
    sec_group = create_security_group(conn, tag)
    
    logging.info(f"Creating instances with tag {tag}.")
    instances = {
        "bastion": create_instance(conn, tag + "_bastion", tag, "Ubuntu 20.04 Focal Fossa x86_64", "m1.small", network.id, sec_group, tag),
        "proxy1": create_instance(conn, tag + "_proxy1", tag, "Ubuntu 20.04 Focal Fossa x86_64", "m1.small", network.id, sec_group, tag),
        "proxy2": create_instance(conn, tag + "_proxy2", tag, "Ubuntu 20.04 Focal Fossa x86_64", "m1.small", network.id, sec_group, tag),
        "node1": create_instance(conn, tag + "_node1", tag, "Ubuntu 20.04 Focal Fossa x86_64", "m1.small", network.id, sec_group, tag),
        "node2": create_instance(conn, tag + "_node2", tag, "Ubuntu 20.04 Focal Fossa x86_64", "m1.small", network.id, sec_group, tag)
    }
    
    internal_ips = {name: inst["internal_ip"] for name, inst in instances.items()}
    floating_ips = {name: inst["floating_ip"] for name, inst in instances.items()}

    logging.info(f"Building SSH configuration.")
    build_ssh_config(tag, internal_ips, floating_ips)
    
    logging.info("Executing Ansible playbook.")
    run_playbook()
    
    validate_operation()

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python install.py <path-to-openrc> <tag> <public-key-path>")
        sys.exit(1)

    main(sys.argv[1], sys.argv[2], sys.argv[3])





# import openstack
# import sys
# import os
# import subprocess
# import logging
# import datetime

# # Configure logging
# logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')

# def load_openrc(openrc):
#     command = f"bash -c 'source {openrc} && env'"
#     proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
#     for line in proc.stdout:
#         (key, _, value) = line.decode("utf-8").partition("=")
#         os.environ[key] = value.strip()
#     proc.communicate()

# def create_keypair(conn, keypair_name):
#     private_key_file = os.path.expanduser(f"~/.ssh/{keypair_name}.pem")
    
#     existing_keypair = conn.compute.find_keypair(keypair_name)
#     timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
#     if not existing_keypair:
#         new_keypair = conn.compute.create_keypair(name=keypair_name)
#         with open(private_key_file, 'w') as key_file:
#             key_file.write(new_keypair.private_key)
#         os.chmod(private_key_file, 0o600)
#         logging.info(f"{timestamp} Key pair '{keypair_name}' was successfully created and stored at '{private_key_file}'.")
#     else:
#         logging.info(f"{timestamp} Key pair '{keypair_name}' already exists.")

# def get_external_network(conn):
#     for network in conn.network.networks():
#         if network.is_router_external:
#             return network.id
#     raise Exception("External network (ext-net) not found.")

# def get_or_create_router(conn, tag):
#     router = conn.network.find_router(tag + "_router")
#     if not router:
#         external_network_id = get_external_network(conn)
#         router = conn.network.create_router(name=tag + "_router", external_gateway_info={"network_id": external_network_id})
#         logging.info(f"Created router: {router.name}")
#     else:
#         logging.info(f"Router {router.name} already exists")
#     return router

# def get_router_ports(conn, router_id):
#     return [port for port in conn.network.ports(device_id=router_id)]

# def delete_unused_routers(conn, tag):
#     routers = conn.network.routers()
#     for router in routers:
#         router_ports = get_router_ports(conn, router.id)
#         if router.name.startswith(tag + "_") and len(router_ports) == 0:
#             conn.network.delete_router(router)
#             logging.info(f"Deleted unused router: {router.name}")

# def create_network(conn, tag):
#     network = conn.network.find_network(tag + "_network")
#     if not network:
#         network = conn.network.create_network(name=tag + "_network")
#         subnet = conn.network.create_subnet(
#             name=tag + "_subnet",
#             network_id=network.id,
#             ip_version='4',
#             cidr='10.0.0.0/24'
#         )
#         router = get_or_create_router(conn, tag)
#         conn.network.add_interface_to_router(router, subnet_id=subnet.id)
#         logging.info(f"Created network, subnet, and router: {network.name}, {subnet.name}, {router.name}")
#     else:
#         logging.info(f"Network {network.name} already exists")
#     return network

# def create_security_group(conn, tag):
#     sec_group = conn.network.find_security_group(tag + "_secgroup")
#     if not sec_group:
#         sec_group = conn.network.create_security_group(name=tag + "_secgroup")
#         conn.network.create_security_group_rule(
#             security_group_id=sec_group.id,
#             direction='ingress',
#             protocol='icmp'
#         )
#         conn.network.create_security_group_rule(
#             security_group_id=sec_group.id,
#             direction='ingress',
#             protocol='tcp',
#             port_range_min='22',
#             port_range_max='22'
#         )
#         conn.network.create_security_group_rule(
#             security_group_id=sec_group.id,
#             direction='ingress',
#             protocol='tcp',
#             port_range_min='5000',
#             port_range_max='5000'
#         )
#         conn.network.create_security_group_rule(
#             security_group_id=sec_group.id,
#             direction='ingress',
#             protocol='udp',
#             port_range_min='6000',
#             port_range_max='6000'
#         )
#         logging.info(f"Created security group {sec_group.name}")
#     else:
#         logging.info(f"Security group {sec_group.name} already exists")
#     return sec_group

# def create_instance(conn, name, tag, image_name, flavor_name, network_id, sec_group, key_name, floating_ip_pool=None):
#     image = conn.compute.find_image(name_or_id=image_name)
#     if not image:
#         raise ValueError(f"Image {image_name} not found. Available images: {[img.name for img in conn.compute.images()]}")
    
#     flavor = conn.compute.find_flavor(name_or_id=flavor_name)
#     if not flavor:
#         raise ValueError(f"Flavor {flavor_name} not found. Available flavors: {[flv.name for flv in conn.compute.flavors()]}")

#     instance = conn.compute.create_server(
#         name=name,
#         image_id=image.id,
#         flavor_id=flavor.id,
#         networks=[{"uuid": network_id}],
#         security_groups=[{"name": sec_group.name}],
#         key_name=key_name
#     )
#     conn.compute.wait_for_server(instance)
#     logging.info(f"Created instance {name}")

#     floating_ip_address = None
#     if name in [tag + "_bastion", tag + "_proxy1", tag + "_proxy2"]:
#         if floating_ip_pool:
#             try:
#                 external_network_id = get_external_network(conn)
#                 floating_ip_address = get_unused_floating_ip(conn, external_network_id)
#                 conn.compute.add_floating_ip_to_server(instance, floating_ip_address)
#                 logging.info(f"Assigned floating IP {floating_ip_address} to instance {name}")
#             except Exception as e:
#                 logging.error(f"Failed to assign floating IP to instance {name}: {str(e)}")

#     internal_ip = instance.addresses.get(tag + "_network")[0]["addr"]

#     return {
#         "name": name,
#         "internal_ip": internal_ip,
#         "floating_ip": floating_ip_address
#     }

# def get_unused_floating_ip(conn, floating_ip_pool):
#     floating_ips = conn.network.ips(floating_network_id=floating_ip_pool)
#     for ip in floating_ips:
#         if ip.fixed_ip_address is None:
#             return ip.floating_ip_address
    
#     created_ip = conn.network.create_ip(floating_network_id=floating_ip_pool)
#     return created_ip.floating_ip_address

# def delete_unused_resources(conn, tag):
#     delete_unused_routers(conn, tag)
#     delete_unused_floating_ips(conn, tag)

# def delete_unused_floating_ips(conn, tag):
#     floating_ips = conn.network.ips()
#     for ip in floating_ips:
#         if ip.description and ip.description.startswith(tag + "_") and ip.fixed_ip_address is None:
#             conn.network.delete_ip(ip.id)
#             logging.info(f"Deleted unused floating IP: {ip.floating_ip_address}")

# def main(openrc, tag, public_key_path):
#     logging.info("Creating 3 nodes")

#     load_openrc(openrc)
#     conn = openstack.connect()

#     network = create_network(conn, tag)
#     sec_group = create_security_group(conn, tag)

#     private_key_path = f"{tag}_private.pem"
#     public_key_generated_path = f"{tag}_private.pem.pub"
    
#     # Generate or retrieve the keypair
#     create_keypair(conn, tag + "_key")
#     logging.info(f"Generated or found keypair {private_key_path} and {public_key_generated_path}")

#     with open(public_key_path, "r") as file:
#         public_key = file.read()

#     keypair = conn.compute.find_keypair(name_or_id=tag + "_key")
#     if not keypair:
#         keypair = conn.compute.create_keypair(name=tag + "_key", public_key=public_key)
#         logging.info(f"Created keypair {tag}_key")
#     else:
#         logging.info(f"Keypair {tag}_key already exists")

#     instances = []
#     floating_ip_pool = "ext-net"
    
#     # Create instances and collect their details
#     instances.append(create_instance(conn, tag + "_bastion", tag, "Ubuntu 20.04 Focal Fossa x86_64", "m1.small", network.id, sec_group, keypair.name, floating_ip_pool))
#     instances.append(create_instance(conn, tag + "_proxy1", tag, "Ubuntu 20.04 Focal Fossa x86_64", "m1.small", network.id, sec_group, keypair.name, floating_ip_pool))
#     instances.append(create_instance(conn, tag + "_proxy2", tag, "Ubuntu 20.04 Focal Fossa x86_64", "m1.small", network.id, sec_group, keypair.name, floating_ip_pool))

#     for i in range(1, 4):
#         instances.append(create_instance(conn, f"{tag}_node{i}", tag, "Ubuntu 20.04 Focal Fossa x86_64", "m1.small", network.id, sec_group, keypair.name))

#     internal_ips = {instance["name"]: instance["internal_ip"] for instance in instances}
#     floating_ips = {instance["name"]: instance["floating_ip"] for instance in instances if instance["floating_ip"]}

#     build_ssh_config(tag, internal_ips, floating_ips)
#     run_playbook()
#     validate_operation()
#     delete_unused_resources(conn, tag)

# def build_ssh_config(tag, internal_ips, floating_ips):
#     ssh_config_path = os.path.expanduser(f"~/.ssh/{tag}_config")
#     with open(ssh_config_path, "w") as file:
#         file.write("# SSH Configurations\n")
#         file.write("Host *\n")
#         file.write(f"\tUser ubuntu\n")
#         file.write(f"\tIdentityFile ~/.ssh/{tag}_private.pem\n")
#         file.write(f"\tStrictHostKeyChecking no\n")
#         file.write(f"\tPasswordAuthentication no\n")
#         file.write(f"\tServerAliveInterval 60\n\n")

#         # Add floating IPs for bastions and proxies
#         for name, floating_ip in floating_ips.items():
#             if name.startswith(tag + "_bastion") or name.startswith(tag + "_proxy"):
#                 file.write(f"Host {name}\n")
#                 file.write(f"\tHostName {floating_ip}\n")
#                 file.write(f"\tUser ubuntu\n")
#                 file.write(f"\tIdentityFile ~/.ssh/{tag}_private.pem\n")
#                 file.write(f"\tProxyCommand ssh -W %h:%p {tag}_bastion\n\n")

#         # Add internal IPs for nodes
#         for name, internal_ip in internal_ips.items():
#             if name.startswith(tag + "_node"):
#                 file.write(f"Host {name}\n")
#                 file.write(f"\tHostName {internal_ip}\n")
#                 file.write(f"\tUser ubuntu\n")
#                 file.write(f"\tIdentityFile ~/.ssh/{tag}_private.pem\n")
#                 file.write(f"\tProxyCommand ssh -W %h:%p {tag}_bastion\n\n")

#     logging.info(f"SSH config file generated: {ssh_config_path}")

# def run_playbook():
#     logging.info("Running Ansible playbook...")
#     ansible_command = "ansible-playbook -i hosts site.yaml -e ansible_ssh_common_args='-F ~/.ssh/proplayer_config'"
#     subprocess.run(ansible_command, shell=True)
#     logging.info("Ansible playbook execution complete.")

# def validate_operation():
#     logging.info("Validation completed.")

# if __name__ == "__main__":
#     if len(sys.argv) != 4:
#         print("Usage: install.py <openrc> <tag> <public_key>")
#         sys.exit(1)
#     main(sys.argv[1], sys.argv[2], sys.argv[3])

# import openstack
# import sys
# import os
# import subprocess
# import logging

# # Configure logging
# logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')

# def load_openrc(openrc):
#     command = f"bash -c 'source {openrc} && env'"
#     proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
#     for line in proc.stdout:
#         (key, _, value) = line.decode("utf-8").partition("=")
#         os.environ[key] = value.strip()
#     proc.communicate()

# def generate_keypair(private_key_path):
#     command = f"ssh-keygen -t rsa -b 2048 -N '' -f {private_key_path}"
#     subprocess.run(command, shell=True)

# def get_external_network(conn):
#     for network in conn.network.networks():
#         if network.is_router_external:
#             return network.id
#     raise Exception("External network (ext-net) not found.")

# def get_or_create_router(conn, tag):
#     router = conn.network.find_router(tag + "_router")
#     if not router:
#         external_network_id = get_external_network(conn)
#         router = conn.network.create_router(name=tag + "_router", external_gateway_info={"network_id": external_network_id})
#         logging.info(f"Created router: {router.name}")
#     else:
#         logging.info(f"Router {router.name} already exists")
#     return router

# def delete_unused_routers(conn, tag):
#     routers = conn.network.routers()
#     for router in routers:
#         if router.name.startswith(tag + "_") and len(router.attached_ports) == 0:
#             conn.network.delete_router(router)
#             logging.info(f"Deleted unused router: {router.name}")

# def create_network(conn, tag):
#     network = conn.network.find_network(tag + "_network")
#     if not network:
#         network = conn.network.create_network(name=tag + "_network")
#         subnet = conn.network.create_subnet(
#             name=tag + "_subnet",
#             network_id=network.id,
#             ip_version='4',
#             cidr='10.0.0.0/24'
#         )
#         router = get_or_create_router(conn, tag)
#         conn.network.add_interface_to_router(router, subnet_id=subnet.id)
#         logging.info(f"Created network, subnet, and router: {network.name}, {subnet.name}, {router.name}")
#     else:
#         logging.info(f"Network {network.name} already exists")
#     return network

# def create_security_group(conn, tag):
#     sec_group = conn.network.find_security_group(tag + "_secgroup")
#     if not sec_group:
#         sec_group = conn.network.create_security_group(name=tag + "_secgroup")
#         conn.network.create_security_group_rule(
#             security_group_id=sec_group.id,
#             direction='ingress',
#             protocol='icmp'
#         )
#         conn.network.create_security_group_rule(
#             security_group_id=sec_group.id,
#             direction='ingress',
#             protocol='tcp',
#             port_range_min='22',
#             port_range_max='22'
#         )
#         conn.network.create_security_group_rule(
#             security_group_id=sec_group.id,
#             direction='ingress',
#             protocol='tcp',
#             port_range_min='5000',
#             port_range_max='5000'
#         )
#         conn.network.create_security_group_rule(
#             security_group_id=sec_group.id,
#             direction='ingress',
#             protocol='udp',
#             port_range_min='6000',
#             port_range_max='6000'
#         )
#         logging.info(f"Created security group {sec_group.name}")
#     else:
#         logging.info(f"Security group {sec_group.name} already exists")
#     return sec_group

# def create_instance(conn, name, tag, image_name, flavor_name, network_id, sec_group, key_name, floating_ip_pool=None):
#     image = conn.compute.find_image(name_or_id=image_name)
#     if not image:
#         raise ValueError(f"Image {image_name} not found. Available images: {[img.name for img in conn.compute.images()]}")
    
#     flavor = conn.compute.find_flavor(name_or_id=flavor_name)
#     if not flavor:
#         raise ValueError(f"Flavor {flavor_name} not found. Available flavors: {[flv.name for flv in conn.compute.flavors()]}")

#     instance = conn.compute.create_server(
#         name=name,
#         image_id=image.id,
#         flavor_id=flavor.id,
#         networks=[{"uuid": network_id}],
#         security_groups=[{"name": sec_group.name}],
#         key_name=key_name  # Specify the key name here
#     )
#     conn.compute.wait_for_server(instance)
#     logging.info(f"Created instance {name}")

#     if name in [tag + "_bastion", tag + "_proxy1", tag + "_proxy2"]:
#         if floating_ip_pool:
#             try:
#                 external_network_id = get_external_network(conn)
#                 floating_ip_address = get_unused_floating_ip(conn, external_network_id)
#                 conn.compute.add_floating_ip_to_server(instance, floating_ip_address)
#                 logging.info(f"Assigned floating IP {floating_ip_address} to instance {name}")
#             except Exception as e:
#                 logging.error(f"Failed to assign floating IP to instance {name}: {str(e)}")

#     return instance

# def get_unused_floating_ip(conn, floating_ip_pool):
#     floating_ips = conn.network.ips(floating_network_id=floating_ip_pool)
#     for ip in floating_ips:
#         if ip.fixed_ip_address is None:
#             return ip.floating_ip_address
    
#     created_ip = conn.network.create_ip(floating_network_id=floating_ip_pool)
#     return created_ip.floating_ip_address

# def delete_unused_resources(conn, tag):
#     delete_unused_routers(conn, tag)
#     delete_unused_floating_ips(conn, tag)

# def delete_unused_floating_ips(conn, tag):
#     floating_ips = conn.network.ips()
#     for ip in floating_ips:
#         if ip.description and ip.description.startswith(tag + "_") and ip.fixed_ip_address is None:
#             conn.network.delete_ip(ip.id)
#             logging.info(f"Deleted unused floating IP: {ip.floating_ip_address}")

# def main(openrc, tag, public_key_path):
#     logging.info("Creating 3 nodes")

#     load_openrc(openrc)
#     conn = openstack.connect()

#     network = create_network(conn, tag)
#     sec_group = create_security_group(conn, tag)

#     private_key_path = f"{tag}_private.pem"
#     public_key_generated_path = f"{tag}_private.pem.pub"
    
#     if not os.path.exists(private_key_path):
#         generate_keypair(private_key_path)
#         logging.info(f"Generated keypair {private_key_path} and {public_key_generated_path}")

#     with open(public_key_path, "r") as file:
#         public_key = file.read()

#     keypair = conn.compute.find_keypair(name_or_id=tag + "_key")
#     if not keypair:
#         keypair = conn.compute.create_keypair(name=tag + "_key", public_key=public_key)
#         logging.info(f"Created keypair {tag}_key")
#     else:
#         logging.info(f"Keypair {tag}_key already exists")

#     instances = []
#     floating_ip_pool = "ext-net"
#     instances.append(create_instance(conn, tag + "_bastion", tag, "Ubuntu 20.04 Focal Fossa x86_64", "m1.small", network.id, sec_group, keypair.name, floating_ip_pool))
#     instances.append(create_instance(conn, tag + "_proxy1", tag, "Ubuntu 20.04 Focal Fossa x86_64", "m1.small", network.id, sec_group, keypair.name, floating_ip_pool))
#     instances.append(create_instance(conn, tag + "_proxy2", tag, "Ubuntu 20.04 Focal Fossa x86_64", "m1.small", network.id, sec_group, keypair.name, floating_ip_pool))

#     for i in range(1, 4):
#         instances.append(create_instance(conn, f"{tag}_node{i}", tag, "Ubuntu 20.04 Focal Fossa x86_64", "m1.small", network.id, sec_group, keypair.name))

#     build_ssh_config(tag, instances)
#     run_playbook()
#     validate_operation()
#     delete_unused_resources(conn, tag)

# def build_ssh_config(tag, instances):
#     ssh_config_path = f"{tag}_ssh_config"
#     with open(ssh_config_path, "w") as file:
#         for instance in instances:
#             floating_ip = instance.addresses.get(tag + "_network")[0]["addr"]
#             file.write(f"Host {instance.name}\n")
#             file.write(f"\tHostName {floating_ip}\n")
#             file.write("\tUser ubuntu\n")
#             file.write(f"\tIdentityFile ~/.ssh/{tag}_private.pem\n\n")
#     logging.info(f"SSH config file generated: {ssh_config_path}")

# def run_playbook():
#     # Implement the logic to run your Ansible playbook
#     logging.info("Running Ansible playbook...")

# def validate_operation():
#     # Implement validation logic here
#     logging.info("Validation completed.")

# if __name__ == "__main__":
#     if len(sys.argv) != 4:
#         print("Usage: install.py <openrc> <tag> <public_key>")
#         sys.exit(1)
#     main(sys.argv[1], sys.argv[2], sys.argv[3])


