import ipaddress


def in_network(ip: str, cidr: str) -> bool:
    # Input validation
    if not isinstance(ip, str) or not isinstance(cidr, str):
        return False
        
    try:
        # Convert strings to ipaddress objects
        ip_obj = ipaddress.ip_address(ip)
        network_obj = ipaddress.ip_network(cidr, strict=False)
        
        # Check if the IP belongs to the network
                # Check if the IP belongs to the network
        return ip_obj in network_obj
            
    # Catch invalid IP or CIDR formats
    except ValueError:
        return False