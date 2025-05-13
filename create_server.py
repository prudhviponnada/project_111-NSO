import logging
from network_files import get_external_network
from network_files import get_unused_floating_ip

def server_exists(conn, server_name):
    """
    Checks if a server with the given name already exists.
    """
    server = conn.compute.find_server(server_name)
    if server:
        return server
    return False

def create_instance_if_not_exists(conn, name, tag, image_name, flavor_name, network_id, sec_group, key_name, floating_ip_pool=None, allowed_address = None):
    """
    Creates a server if it doesn't already exist.
    """
    key_name = str(key_name) + "_key"
    check_server = server_exists(conn, name)
    if check_server:
        logging.info(f"Server '{name}' already exists. Skipping creation.")
        try: 
            floating_ip = check_server.addresses.get(tag + "_network")[1]["addr"]
        except Exception as e:
            floating_ip = None
              
        return {
        "name": name,
        "internal_ip": check_server.addresses.get(tag + "_network")[0]["addr"],
        "floating_ip": floating_ip
    }

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
    internal_ip = instance.addresses.get(tag + "_network")[0]["addr"]
    floating_ip_address = None
    
    if floating_ip_pool:
        try:
            external_network_id = get_external_network(conn)
            floating_ip = get_unused_floating_ip(conn, external_network_id)
            port = list(conn.network.ports(device_id=instance.id))
            conn.network.update_ip(floating_ip, port_id=port[0].id)
            floating_ip_address = floating_ip.floating_ip_address
            logging.info(f"Assigned floating IP {floating_ip_address} to instance {name}")
        except Exception as e:
            logging.error(f"Failed to assign floating IP to instance {name}: {str(e)}")

    logging.info(f"Instance {name} - Internal IP: {internal_ip}, Floating IP: {floating_ip_address}")
    if name == tag+'_proxy1' or name == tag+'_proxy2':
        port = list(conn.network.ports(device_id=instance.id))
        conn.network.update_port(port[0].id, allowed_address_pairs=[{"ip_address": allowed_address}])
        
    return {
        "name": name,
        "internal_ip": internal_ip,
        "floating_ip": floating_ip_address
    }
    