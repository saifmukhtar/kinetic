import os

files_to_fix = [
    'kinetic-core/tests/test_021_subdomain_hijack.rs',
    'kinetic-core/tests/test_003_oom_payload_bomb.rs',
    'kinetic-core/tests/test_029_protocol_downgrade.rs'
]

for file_path in files_to_fix:
    with open(file_path, 'r') as file:
        content = file.read()
    
    if 'RevealExt' not in content:
        new_content = 'use kinetic_core::types::RevealExt;\n' + content
        with open(file_path, 'w') as file:
            file.write(new_content)
        print(f"Updated {file_path}")
