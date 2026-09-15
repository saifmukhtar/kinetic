//! Internal event handlers for `NetworkEventLoop`.
//!
//! ## Layer 7 Architecture: The Event Handlers
//! To prevent `event_loop/core.rs` from growing into an unmaintainable monolith, all 
//! `libp2p::SwarmEvent` logic is delegated to specific sub-handlers here.
//!
//! ## Subsystem Responsibilities
//! - **`gossipsub`**: The heavy flood router. It intercepts globally flooded network messages 
//!   (like Time Oracle pulses or Global Action states). Note that it explicitly ignores 
//!   standard namespace Reveals, which are routed exclusively through the DHT.
//! - **`kademlia`**: The DHT navigator. It manages the `RecordStore` interactions, peer 
//!   discovery, and the `put_record` flows for sovereign `.kin` domains.
//! - **`action_sync`**: The consensus upgrade state machine. It handles requests to pause 
//!   or resume the network, ensuring the global `kinetic-local::action` state remains synced 
//!   across the swarm.
//! - **`cdn` & `proxy`**: The privacy and edge-delivery pipelines for standard web traffic 
//!   routed over the Kinetic mesh.

/// Handler for ActionSync events
pub mod action_sync;
pub(crate) mod cdn;
pub(crate) mod gossipsub;
pub(crate) mod kademlia;
pub(crate) mod proxy;
