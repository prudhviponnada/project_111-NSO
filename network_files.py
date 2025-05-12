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

