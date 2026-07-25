import json
import sys

def main():
    with open('network.json', 'r') as f:
        data = json.load(f)

    new_data = {
        "network": {
            "network_id": data.get("network_id"),
            "tld": data.get("tld"),
            "tld_suffix": data.get("tld_suffix"),
            "did_prefix": data.get("did_prefix"),
            "base_domain": data.get("base_domain"),
            "docs_url": data.get("docs_url"),
            "ipfs_gateway": data.get("ipfs_gateway"),
            "default_bind_ip": data.get("default_bind_ip"),
            "dns_ip": data.get("dns_ip"),
            "bootstrap_nodes": data.get("bootstrap_nodes")
        },
        "crypto": {
            "prod_root_public_key_hex": data.get("prod_root_public_key_hex"),
            "prod_guard_public_key_hex": data.get("prod_guard_public_key_hex"),
            "pow_difficulty_bits": data.get("pow_difficulty_bits"),
            "wallet_pbkdf2_iterations": data.get("crypto", {}).get("wallet_pbkdf2_iterations"),
            "keygen_pbkdf2_iterations": data.get("crypto", {}).get("keygen_pbkdf2_iterations"),
            "argon2_memory_cost_kb": data.get("crypto", {}).get("argon2_memory_cost_kb")
        },
        "drand": {
            "drand_genesis_time": data.get("drand_genesis_time"),
            "drand_period": data.get("drand_period"),
            "kinetic_genesis_drand_round": data.get("kinetic_genesis_drand_round"),
            "drand_public_key": data.get("drand_public_key"),
            "drand_http_endpoints": data.get("drand_http_endpoints")
        },
        "governance": {
            "governance_model": data.get("governance_model"),
            "min_active_council": data.get("min_active_council"),
            "max_council_size": data.get("max_council_size"),
            "max_age_seconds": data.get("max_age_seconds"),
            "timelock_seconds": data.get("timelock_seconds"),
            "active_window_seconds": data.get("active_window_seconds"),
            "ota_timelock_seconds": data.get("ota_timelock_seconds"),
            "supermajority_percent": data.get("governance", {}).get("supermajority_percent"),
            "majority_percent": data.get("governance", {}).get("majority_percent"),
            "strict_majority_percent": data.get("governance", {}).get("strict_majority_percent")
        },
        "consensus": data.get("consensus", {}),
        "advanced": {
            "benchmark_base_iterations": data.get("benchmark_base_iterations"),
            "benchmark_target_minutes": data.get("benchmark_target_minutes"),
            "steal_target_rounds": data.get("steal_target_rounds"),
            "m_redundancy": data.get("m_redundancy"),
            "dev_mode_iterations": data.get("dev_mode_iterations"),
            "limits": data.get("limits", {}),
            "timeouts": data.get("timeouts", {})
        }
    }

    with open('network.json', 'w') as f:
        json.dump(new_data, f, indent=2)
    print("Done")

if __name__ == '__main__':
    main()
