from warmup import in_network


def test_ip_inside_network():
    # Testing a valid IP inside the /24 range
    assert in_network("192.168.1.5", "192.168.1.0/24") is True

def test_ip_outside_network():
    # Testing an IP from a different network
    assert in_network("10.0.0.5", "192.168.1.0/24") is False

def test_invalid_input():
    # Testing a malformed IP address to ensure it doesn't crash
    assert in_network("999.999.1.1", "192.168.1.0/24") is False