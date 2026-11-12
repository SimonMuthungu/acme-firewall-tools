import subprocess


def test_full_audit_output():
    # 1. Run the script and capture its output
    result = subprocess.run(["python", "rule_audit.py"], capture_output=True, check=False, text=True)
    actual_output = result.stdout.strip()

    # 2. Read the saved baseline file
    with open("test/known_good.txt", "r", encoding="utf-8") as f:
        expected_output = f.read().strip()

    # 3. Assert they match exactly
    assert actual_output == expected_output