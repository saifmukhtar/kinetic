import os
import re

directories_to_scan = ['kinetic-network', 'kinetic-daemon', 'kinetic-host', 'kinetic-node']

replacements = [
    (r'\.signable_bytes\(\)', r'.signable_bytes(kinetic_core::constants::NETWORK_ID)'),
    (r'derive_storage_keys\(([^,)]+)\)', r'derive_storage_keys(\1, kinetic_core::constants::NETWORK_ID)'),
    (r'derive_heartbeat_keys\(([^,)]+)\)', r'derive_heartbeat_keys(\1, kinetic_core::constants::NETWORK_ID)'),
]

for d in directories_to_scan:
    for root, dirs, files in os.walk(d):
        for f in files:
            if f.endswith('.rs'):
                path = os.path.join(root, f)
                with open(path, 'r') as file:
                    content = file.read()
                
                new_content = content
                for old_pattern, new_pattern in replacements:
                    new_content = re.sub(old_pattern, new_pattern, new_content)
                
                if new_content != content:
                    with open(path, 'w') as file:
                        file.write(new_content)
                    print(f"Updated {path}")
