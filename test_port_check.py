from port_check import compare_port

def test_compare_port_pass():
    # If expected matches actual, it should return a string containing "PASS"
    result = compare_port("22", "OPEN", "OPEN")
    assert "PASS" in result

def test_compare_port_fail():
    # If expected does NOT match actual, it should return a string containing "FAIL"
    result = compare_port("80", "FILTERED", "CLOSED")
    assert "FAIL" in result