use serde::{Deserialize, Serialize};

/// Represents a heartbeat proof indicating that a `.kin` domain is actively maintained by its owner.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    /// Domain name associated with this heartbeat.
    pub name: String,
    /// Latest drand round number proving heartbeat recency.
    pub latest_drand_pulse: u64,
    /// Owner's ML-DSA-65 post-quantum signature over [`signable_bytes`](Heartbeat::signable_bytes).
    pub signature: Vec<u8>,
}

impl Heartbeat {
    /// Serializes this heartbeat payload into a canonical byte string for owner signature verification.
    pub fn signable_bytes(&self, network_id: &str) -> Vec<u8> {
        let prefix_suffix = b"-heartbeat-v1";
        let mut bytes =
            Vec::with_capacity(network_id.len() + prefix_suffix.len() + 4 + self.name.len() + 8);
        bytes.extend_from_slice(network_id.as_bytes());
        bytes.extend_from_slice(prefix_suffix);
        bytes.extend_from_slice(&(self.name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(&self.latest_drand_pulse.to_be_bytes());
        bytes
    }
}

/// Represents the two different ways a domain can be owned on the Kinetic network.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DomainRecord {
    /// A standard domain registered via Proof of Work and VDF.
    Standard(Box<crate::vdf::Reveal>),
    /// A premium domain granted directly by the Governance Root Key.
    Premium {
        /// The domain name.
        name: String,
        /// The ML-DSA-65 public key of the domain owner.
        pubkey: Vec<u8>,
        /// The unix timestamp in seconds when this grant was approved.
        granted_at: u64,
        /// The zone payload associated with the domain.
        payload: Vec<u8>,
        /// The owner's ML-DSA-65 signature authorizing the payload.
        signature: Vec<u8>,
    },
}

impl DomainRecord {
    /// Returns the domain name.
    pub fn name(&self) -> &str {
        match self {
            Self::Standard(r) => &r.name,
            Self::Premium { name, .. } => name,
        }
    }

    /// Returns the public key of the owner.
    pub fn pubkey(&self) -> &[u8] {
        match self {
            Self::Standard(r) => &r.pubkey,
            Self::Premium { pubkey, .. } => pubkey,
        }
    }

    /// Returns the zone payload.
    pub fn payload(&self) -> &[u8] {
        match self {
            Self::Standard(r) => &r.payload,
            Self::Premium { payload, .. } => payload,
        }
    }

    /// Returns the ML-DSA-65 signature.
    pub fn signature(&self) -> &[u8] {
        match self {
            Self::Standard(r) => &r.signature,
            Self::Premium { signature, .. } => signature,
        }
    }

    /// Verifies the ownership signature attached to this domain record.
    pub fn verify_signature(&self, network_id: &str) -> Result<(), crate::vdf::VdfVerifyError> {
        match self {
            Self::Standard(reveal) => reveal.verify_signature(network_id),
            Self::Premium {
                name,
                payload,
                signature,
                pubkey,
                ..
            } => {
                use ml_dsa::signature::Verifier;
                use ml_dsa::KeyInit;
                let verifying_key = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::new_from_slice(pubkey)
                    .map_err(|_| crate::vdf::VdfVerifyError::MalformedPublicKey)?;

                let sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(signature.as_slice())
                    .map_err(|_| crate::vdf::VdfVerifyError::MalformedSignature)?;

                let mut signable = Vec::new();
                signable.extend_from_slice(name.as_bytes());
                signable.extend_from_slice(payload);
                signable.extend_from_slice(network_id.as_bytes());

                verifying_key
                    .verify(&signable, &sig)
                    .map_err(|_| crate::vdf::VdfVerifyError::InvalidSignature)
            }
        }
    }
}
