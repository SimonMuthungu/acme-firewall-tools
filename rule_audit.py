import csv
from dataclasses import dataclass

@dataclass
class Rule:
    priority: int
    source: str
    destination: str
    protocol: str
    port: str
    action: str
    logging: str
    comment: str
    hits: int

def parse_port(port_str: str):
    """Handles single ports and ranges like 8080-8090."""
    if port_str == "ANY":
        return "ANY"
    if "-" in port_str:
        start, end = port_str.split("-")
        return (int(start), int(end))
    return int(port_str)

def load_rules(filepath):
    rules = []
    with open(filepath, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # clean up whitespace in case the CSV is messy
            clean_row = {k.strip(): v.strip() for k, v in row.items() if k}
            
            rule = Rule(
                priority=int(clean_row['priority']),
                source=clean_row['source'],
                destination=clean_row['destination'],
                protocol=clean_row['protocol'],
                port=clean_row['port'],
                action=clean_row['action'],
                logging=clean_row['logging'],
                comment=clean_row['comment'],
                hits=int(clean_row['hits_14d_business_hours'])
            )
            rules.append(rule)
    return rules

def audit_rules(rules):
    findings = []
    
    for rule in rules:
        # We only care about ALLOW rules for these checks
        if rule.action.upper() != "ALLOW":
            continue
            
        flags = []
        
        # 1. Check for ANY_ANY
        if rule.source == "ANY" and rule.destination == "ANY" and rule.port == "ANY":
            flags.append("ANY_ANY")
            
        # 2. Check for INSECURE_PORT
        insecure_ports = ["21", "23", "80", "3389"]
        if rule.port in insecure_ports:
            flags.append("INSECURE_PORT")
            
        # 3. Check for NO_LOGGING
        if rule.logging.lower() in ["no", "false"]:
            flags.append("NO_LOGGING")
            
        # 4. Check for WIDE_PORT_RANGE
        parsed_port = parse_port(rule.port)
        if isinstance(parsed_port, tuple):
            start, end = parsed_port
            if (end - start) > 5:
                flags.append("WIDE_PORT_RANGE")
                
        # If we found any issues, save the rule and its flags
        if flags:
            findings.append({
                "priority": rule.priority,
                "rule": rule,
                "flags": flags
            })
            
    return findings

if __name__ == "__main__":
    # Load the rules
    rules = load_rules("data/acme_rules.csv")
    
    # Run the audit
    findings = audit_rules(rules)
    
    # Print a readable summary
    print("--- Rule Audit Summary ---")
    for finding in findings:
        print(f"Rule {finding['priority']}: {finding['flags']}")