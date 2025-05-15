import logging
def get_external_network(conn):
    for network in conn.network.networks():
        if network.is_router_external:
            return network.id
    raise Exception("External network (ext-net) not found.")

def get_unused_floating_ip(conn, floating_ip_pool, fixed_ip= None):
    floating_ips = conn.network.ips(floating_network_id=floating_ip_pool)
    for ip in floating_ips:
        if fixed_ip and fixed_ip == ip.fixed_ip_address:
            return ip
        if ip.fixed_ip_address is None:
            return ip
    created_ip = conn.network.create_ip(floating_network_id=floating_ip_pool)
    return created_ip

def get_or_create_router(conn, tag):
    router = conn.network.find_router(tag + "_router")
    if not router:
        external_network_id = get_external_network(conn)
        router = conn.network.create_router(name=tag + "_router", external_gateway_info={"network_id": external_network_id})
        logging.info(f"Created router: {router.name}")
    else:
        logging.info(f"Router {router.name} already exists")
    return router

def create_network(conn, tag):
    network = conn.network.find_network(tag + "_network")
    if network: 
        subnet = conn.network.find_subnet(tag+"_subnet")
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
    return network, subnet

