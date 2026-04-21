import re

with open('wf_np_tests.yaml', 'r') as f:
    content = f.read()

# Pattern: Find lookup/PATCH steps that don't have a sleep before them
# Add sleep before Step 1 lookup operations (after Precondition)
content = re.sub(
    r'(expected_status: 200\n\n      - name: "Step 1 [^"]*Lookup)',
    r'expected_status: 200\n\n      - name: "Wait for propagation"\n        sleep_seconds: 5\n\n      - name: "Step 1 Lookup',
    content
)

# Add sleep before PATCH operations (Step 2/Step 3)
content = re.sub(
    r'(expected_status: 200\n\n      - name: "Step [23] [^"]*PATCH)',
    r'expected_status: 200\n\n      - name: "Wait for propagation"\n        sleep_seconds: 3\n\n      - name: "Step \g<1>PATCH',
    content
)

with open('wf_np_tests.yaml', 'w') as f:
    f.write(content)

print("Added sleep delays before lookup and PATCH operations")
