# Error Codes

This reference lists the common error codes you might encounter when using the Kinetic CLI, along with simple instructions on how to fix them.

## Name Resolution (KIN-RES)

| Error Code | What it means | Fix |
| :--- | :--- | :--- |
| **KIN-RES-001** | **Offline.** Your node cannot reach the network to look up the name. | Check your internet connection and ensure port `6070` is not blocked by a firewall. |
| **KIN-RES-002** | **Not Found.** The domain doesn't exist on the network. | Check the spelling of the name. If you just registered it, make sure you ran `kinetic name publish`. |
| **KIN-RES-003** | **Verification Failed.** The name data appears tampered with. | Wait a few minutes and try again. The network may be propagating updates. |
| **KIN-RES-004** | **Expired.** The name's registration has expired. | If you own the name, run `kinetic name renew`. |
| **KIN-RES-005** | **Timeout.** The network took too long to respond. | Try the command again. |
| **KIN-RES-006** | **Internal Error.** An internal software error occurred. | Restart the daemon. |

## Name Publishing (KIN-PUB)

| Error Code | What it means | Fix |
| :--- | :--- | :--- |
| **KIN-PUB-001** | **Offline.** Cannot publish your changes to the network. | Check your internet connection. |
| **KIN-PUB-002** | **Invalid VDF Proof.** The computation attached to your publish is bad. | You may have corrupted your `.reveal.json` file. |
| **KIN-PUB-003** | **Already Owned.** Someone else owns this name. | You cannot publish records for a name you don't own. |
| **KIN-PUB-004** | **Publish Failed.** The network rejected your updates. | Ensure your daemon is fully synced and try again. |
| **KIN-PUB-005** | **Internal Error.** A configuration error prevented publishing. | Check daemon logs and restart. |

## Registration (KIN-REG)

| Error Code | What it means | Fix |
| :--- | :--- | :--- |
| **KIN-REG-001** | **Invalid Name.** The name format is bad. | Use only lowercase letters, digits, and hyphens. |
| **KIN-REG-002** | **Computation Failed.** The heavy VDF math failed. | Check if your machine has sufficient RAM/CPU, or restart the daemon. |
| **KIN-REG-003** | **Commitment Mismatch.** Registration data got mixed up. | Delete the local zone files for this name and restart the registration. |
| **KIN-REG-004** | **Already Owned.** Someone else registered this name first. | Choose a different name. |
| **KIN-REG-005** | **In Progress.** You are already computing a name. | Only one VDF task can run at a time. Wait for it to finish. |
| **KIN-REG-006** | **Rejected.** The network refused your registration. | Check the specific error message provided. |
| **KIN-REG-007** | **Internal Error.** An unexpected issue occurred. | Restart the daemon and try again. |

## Network (KIN-NET)

| Error Code | What it means | Fix |
| :--- | :--- | :--- |
| **KIN-NET-001** | **Timeout.** A network request took too long. | Try again. |
| **KIN-NET-002** | **Offline.** Node has no reachable peers. | Check your internet connection. |
| **KIN-NET-003** | **Routing Table Empty.** Cannot find any peers to talk to. | Check if your firewall is blocking outbound traffic. Restart the daemon. |
| **KIN-NET-004..009** | **Internal Network Errors.** Various low-level connection issues. | Restart the daemon if the issue persists. |

## Storage (KIN-STO)

| Error Code | What it means | Fix |
| :--- | :--- | :--- |
| **KIN-STO-001** | **Database Locked.** Another daemon is running. | Close other terminals or kill the existing `kinetic-daemon` process. |
| **KIN-STO-002** | **Storage Corruption.** Local database is corrupted. | The daemon will usually reset this automatically. If not, delete the `sled_db` folder. |
| **KIN-STO-003** | **Operation Failed.** Disk read/write error. | Check your hard drive space and permissions. |

## VDF Math (KIN-VDF)

| Error Code | What it means | Fix |
| :--- | :--- | :--- |
| **KIN-VDF-001/002** | **Lock Error.** Another VDF task is holding the CPU. | Wait for the current registration/renewal to finish. |
| **KIN-VDF-003..004** | **Math Errors.** The computation engine crashed. | Restart the daemon. Ensure your CPU is not overheating or unstable. |
| **KIN-VDF-005** | **Unsupported Platform.** VDF math doesn't support your OS/CPU. | Run Kinetic on a standard Linux, macOS, or Windows machine (x86_64 or ARM64). |

## Randomness (KIN-DRA)

| Error Code | What it means | Fix |
| :--- | :--- | :--- |
| **KIN-DRA-001/002** | **Endpoints Failed / Network Error.** Cannot reach the randomness beacon on the internet. | Check your internet connection. Ensure you can reach `drand.cloudflare.com`. |
| **KIN-DRA-004** | **No Cached Pulse.** You are offline and have no saved randomness. | Connect to the internet. |

## DNS Zones (KIN-DNS)

| Error Code | What it means | Fix |
| :--- | :--- | :--- |
| **KIN-DNS-001/002** | **Bad JSON.** Your zone file has a syntax error. | Check your commas and brackets in the `zones/NAME.json` file. |
| **KIN-DNS-003** | **Too Many Records.** Exceeded the limit of 50. | Remove some records from your zone file. |
| **KIN-DNS-004/005** | **Invalid Label.** A subdomain name is too long or has bad characters. | Use standard lowercase characters for subdomains. |
| **KIN-DNS-006/008** | **Invalid CNAME.** Bad CNAME configuration. | A CNAME cannot exist alongside other records (like A or TXT) for the same label. |
| **KIN-DNS-007** | **TXT Too Long.** Text record exceeds 255 bytes. | Shorten your TXT record. |
| **KIN-DNS-009/010** | **Invalid PeerId / KID.** Malformed identity record. | Double-check the string you copied. |

## Identity (KIN-IDN)

| Error Code | What it means | Fix |
| :--- | :--- | :--- |
| **KIN-IDN-001/002** | **File Error / Corruption.** Your `identity.key` is missing or broken. | Restore from your seed phrase using `kinetic seed restore`. |
| **KIN-IDN-003** | **Identity Not Found.** No identity exists yet. | Run `kinetic seed init` to create one. |
| **KIN-IDN-004** | **Invalid Seed Phrase.** You typed your backup words incorrectly. | Check for typos. Words must be exactly from the BIP-39 list. |

## Name Formatting (KIN-NAM)

| Error Code | What it means | Fix |
| :--- | :--- | :--- |
| **KIN-NAM-001/002** | **Name/Label Too Long.** | Keep names shorter than 253 chars, and labels under 63 chars. |
| **KIN-NAM-003** | **Invalid Character.** | Use only lowercase letters, numbers, and hyphens. |
| **KIN-NAM-004/005** | **Reserved Name.** The name is protected for network use. | Choose a different name. |
| **KIN-NAM-006** | **Invalid TLD.** | Name must end in `.kin`. |
| **KIN-NAM-007** | **Not An Apex Domain.** You are trying to act on a subdomain. | You must register the apex domain (e.g. `foo.kin`, not `sub.foo.kin`). |

## Internal (KIN-API / KIN-IMPL)

| Error Code | What it means | Fix |
| :--- | :--- | :--- |
| **KIN-IMPL-001** | **RNG Failure.** OS failed to generate random numbers. | Restart your computer or check OS health. |
| **KIN-IMPL-005** | **Zone Write Failed.** Could not save zone file. | Check disk permissions in your data directory. |
| **KIN-API-001** | **Warning.** A minor network fetch failed but was handled. | No action needed. |
