import logging
def create_security_group(conn, tag, subnet):
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
        conn.network.create_security_group_rule(
            security_group_id=sec_group.id,
            direction='ingress',
            protocol='udp',
            port_range_min='161',
            port_range_max='161',
            remote_ip_prefix = subnet.cidr
        )
        conn.network.create_security_group_rule(
            security_group_id=sec_group.id,
            direction='ingress',
            protocol='tcp',
            port_range_min='5000',
            port_range_max='5000',
            remote_ip_prefix = subnet.cidr
        )
        conn.network.create_security_group_rule(
            security_group_id=sec_group.id,
            direction='ingress',
            protocol='tcp',
            port_range_min='22',
            port_range_max='22',
            remote_ip_prefix = subnet.cidr
        )
        conn.network.create_security_group_rule(
            security_group_id=sec_group.id,
            direction='ingress',
            protocol='VRRP',
            remote_ip_prefix = subnet.cidr
        )
        conn.network.create_security_group_rule(
            security_group_id=sec_group.id,
            direction='ingress',
            protocol='tcp',
            port_range_min='9100',
            port_range_max='9100',
            remote_ip_prefix = subnet.cidr
        )
        conn.network.create_security_group_rule(
            security_group_id=sec_group.id,
            direction='ingress',
            protocol='tcp',
            port_range_min='9090',
            port_range_max='9090'
        )
        logging.info(f"Created security group {sec_group.name}")
    else:
        logging.info(f"Security group {sec_group.name} already exists")
    return sec_group