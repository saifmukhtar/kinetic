import re

with open("kinetic-core/src/governance/tests.rs", "r") as f:
    content = f.read()

# Replace timestamp_sec with timestamp_kyn
content = content.replace("timestamp_sec:", "timestamp_kyn:")

# Replace process_governance_message calls to include the third argument
content = re.sub(r'process_governance_message\(&mut state, &(.*?)\)', r'process_governance_message(&mut state, &\1, \1.timestamp_kyn)', content)

# Replace current_time with current_kyn for clarity
content = content.replace("current_time", "current_kyn")

with open("kinetic-core/src/governance/tests.rs", "w") as f:
    f.write(content)
