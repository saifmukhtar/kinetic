# kinetic-node: Headless Infrastructure Node

While the `kinetic-daemon` is designed for end-users running on local machines, the Kinetic network also relies on robust, long-lived infrastructure nodes to maintain DHT stability and provide consistent bootstrap points. This is the purpose of `kinetic-node`.

## Architecture & Purpose

`kinetic-node` is a specialized headless daemon optimized for cloud servers (e.g., AWS, DigitalOcean). It differs from the standard daemon in several critical ways:

### 1. Static Keys and Sybil PoW Bypass
Standard nodes must compute a Proof-of-Work (PoW) to generate a valid Sybil-resistant Peer ID when joining the DHT. Infrastructure nodes, however, use pre-computed **static keys**. Because these keys are computationally expensive to generate initially but remain static, the `kinetic-node` can restart instantly and consistently use the same Peer ID. This stability is essential for serving as a reliable bootstrap node for the rest of the network.

### 2. FullNode Mode & mDNS Disabled
Unlike a local desktop daemon that might switch between client and full node modes, `kinetic-node` runs strictly in **FullNode** mode. It actively participates in routing, stores DHT records for other peers, and provides bandwidth to the network. 

Additionally, because it operates in cloud environments where multicast traffic is typically blocked or unnecessary, **mDNS discovery is disabled**. It relies entirely on explicit bootstrap peers and DHT routing.

### 3. Health-Check API
To integrate seamlessly with cloud orchestration tools like Kubernetes or Docker Swarm, `kinetic-node` exposes a lightweight Health-check API. It binds a minimal server to port **16003** and responds to `/health` requests. This allows load balancers and container managers to verify that the node is active and participating in the DHT.
