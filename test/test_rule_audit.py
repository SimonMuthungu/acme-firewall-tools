import os

import pytest

from rule_audit import (
    Rule,
    audit_rules,
    check_shadowed,
    load_rules,
    parse_port,
    save_to_csv,
)

# --- Step 1: Port range parsing ---

def test_parse_single_port():
    # A single port should return an integer
    assert parse_port("443") == 443

def test_parse_port_range():
    # A range should return a tuple of two integers
    assert parse_port("8080-8090") == (8080, 8090)



# --- Step 2: Flag Testing (Parameterized) ---

@pytest.mark.parametrize("port, expected_flag", [
    ("23", "INSECURE_PORT"),        # Passing case (23 is bad)
    ("443", None),                  # Non-passing case (443 is safe)
    ("8080-8090", "WIDE_PORT_RANGE"), # Passing case (11 ports, too wide)
    ("8080-8082", None)             # Non-passing case (3 ports, safe)
])
def test_port_flags(port, expected_flag):
    # Build a fake rule with the given port
    rule = Rule(1, "10.0.0.1", "192.168.1.1", "TCP", port, "ALLOW", "yes", "", 0)
    
    # Run the audit
    findings = audit_rules([rule])
    
    # Check if the flag was found (or not found)
    if expected_flag:
        assert expected_flag in findings[0]["flags"]
    else:
        assert len(findings) == 0

# --- Step 3: ANY handling ---

def test_any_any_rule():
    # A rule with ANY for source, dest, and port
    rule = Rule(1, "ANY", "ANY", "TCP", "ANY", "ALLOW", "yes", "", 0)
    findings = audit_rules([rule])
    
    # It should be flagged as ANY_ANY
    assert "ANY_ANY" in findings[0]["flags"]

def test_partial_any_not_flagged():
    # A rule with ANY source, but a specific destination
    rule = Rule(1, "ANY", "192.168.1.0/24", "TCP", "443", "ALLOW", "yes", "", 0)
    findings = audit_rules([rule])
    
    # It should NOT be flagged as ANY_ANY
    assert len(findings) == 0

# --- Step 4: Shadowed Rules ---

def test_rule_completely_shadowed():
    # Rule 1 covers 10.0.0.0/8. Rule 2 is inside that (10.0.0.0/24).
    rule1 = Rule(1, "10.0.0.0/8", "192.168.1.0/24", "TCP", "443", "ALLOW", "yes", "", 0)
    rule2 = Rule(2, "10.0.0.0/24", "192.168.1.0/24", "TCP", "443", "ALLOW", "yes", "", 0)
    
    shadowed = check_shadowed([rule1, rule2])
    assert 2 in shadowed

def test_rule_partly_overlaps_not_shadowed():
    # Rule 1 is smaller (10.0.0.0/24). Rule 2 is bigger (10.0.0.0/8).
    # Rule 2 is NOT shadowed because it covers more than Rule 1.
    rule1 = Rule(1, "10.0.0.0/24", "192.168.1.0/24", "TCP", "443", "ALLOW", "yes", "", 0)
    rule2 = Rule(2, "10.0.0.0/8", "192.168.1.0/24", "TCP", "443", "ALLOW", "yes", "", 0)
    
    shadowed = check_shadowed([rule1, rule2])
    assert len(shadowed) == 0

# --- Step 5: Malformed CSV handling ---

def test_malformed_csv_raises_error(tmp_path):
    # Create a temporary fake CSV with a bad row (letters instead of numbers)
    bad_csv = tmp_path / "bad_rules.csv"
    bad_csv.write_text("priority,source,destination,protocol,port,action,logging,comment,hits_14d_business_hours\n1,10.0.0.0/8,192.168.1.0/24,TCP,443,ALLOW,yes,test,NOT_A_NUMBER")
    
    # Assert that it raises a ValueError (clean error) instead of crashing randomly
    with pytest.raises(ValueError):
        load_rules(str(bad_csv))
        

def test_csv_output(tmp_path):
    # Create a fake finding
    findings = [{"priority": 1, "flags": ["NO_LOGGING"]}]
    
    # Save it to a temporary file
    test_file = tmp_path / "test_report.csv"
    save_to_csv(findings, str(test_file))
    
    # Check that the file was created and has the right text
    assert os.path.exists(test_file)
    with open(test_file, "r") as f:
        content = f.read()
        assert "Rule Priority,Flags" in content
        assert "1,NO_LOGGING" in content