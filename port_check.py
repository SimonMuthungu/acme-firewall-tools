import socket
import json
import sys

def check_port(host, port):
    # Create a TCP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.5) # Wait 1.5 seconds before giving up
    
    try:
        s.connect((host, int(port)))
        return "OPEN"
    except socket.timeout:
        return "FILTERED" # No answer (firewall dropped it)
    except ConnectionRefusedError:
        return "CLOSED" # Server actively rejected it
    finally:
        s.close()

def compare_port(port, expected, actual):
    if expected == actual:
        return f"Port {port}: PASS (Expected {expected}, got {actual})"
    else:
        return f"Port {port}: FAIL (Expected {expected}, got {actual})"

def run_audit(host, json_file):
    with open(json_file, 'r') as f:
        expected_states = json.load(f)
        
    print(f"--- Auditing Host: {host} ---")
    for port, expected in expected_states.items():
        actual = check_port(host, port)
        print(compare_port(port, expected, actual))

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python port_check.py <host_ip> <expected.json>")
        sys.exit(1)
        
    host_ip = sys.argv[1]
    json_file = sys.argv[2]
    run_audit(host_ip, json_file)