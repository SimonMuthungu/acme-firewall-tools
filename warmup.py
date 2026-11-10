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
        if ip_obj in network_obj:
            return True
        else:
            return False
            
    # Catch invalid IP or CIDR formats
    except ValueError:
        return False