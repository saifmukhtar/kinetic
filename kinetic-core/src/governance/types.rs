use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::{HashMap, HashSet};

pub type Hash256 = [u8; 32];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum GovernanceAction {
    AppointMember { key: VerifyingKey },
    UpdateBinary {
        manifest_hash: Hash256,
        version_nonce: u64,
        mirrors: Vec<String>,
    },
    LockCouncil,
    VetoUpdate { target_hash: Hash256 },
    RotateRootKey { new_key: VerifyingKey },
    RotateGuardKey { new_key: VerifyingKey },
    SelfAppointCouncilMember { candidate_key: VerifyingKey },
    RemoveCouncilMember { target_key: VerifyingKey },
    EmergencyReset {
        new_root: VerifyingKey,
        new_guard: VerifyingKey,
        override_mode: bool,
    },
    ExecuteTimelock { target_hash: Hash256 },
    GrantPremiumName {
        name: String,
        target_pubkey: VerifyingKey,
    },
    RevokePremiumName {
        name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceEffect {
    TriggerOTA {
        manifest_hash: Hash256,
        mirrors: Vec<String>,
    },
    PremiumNameGranted {
        name: String,
        target_pubkey: VerifyingKey,
    },
    PremiumNameRevoked {
        name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GovernanceMode {
    Founder,
    Council,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedGovernanceMessage {
    pub action: GovernanceAction,
    pub council_size_at_proposal: u32,
    pub timestamp_sec: u64,
    pub signatures: Vec<Signature>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GovernanceState {
    pub genesis_timestamp_sec: u64,
    pub mode: GovernanceMode,
    pub lock_timestamp_sec: Option<u64>,
    pub active_council: Vec<VerifyingKey>,
    pub last_signature_timestamps: HashMap<VerifyingKey, u64>,
    pub pending_timelocks: HashMap<Hash256, u64>,
    pub vetoed_hashes: HashSet<Hash256>,
    pub pending_updates: HashMap<Hash256, (u64, u64, Vec<String>)>,
    pub partial_proposals: HashMap<Hash256, SignedGovernanceMessage>,
    pub founder_premium_grants: u8,
    pub grace_period_start_sec: Option<u64>,
}

impl SignedGovernanceMessage {
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match &self.action {
            GovernanceAction::AppointMember { key } => {
                buf.push(0x00);
                buf.extend_from_slice(key.as_bytes());
            }
            GovernanceAction::UpdateBinary {
                manifest_hash,
                version_nonce,
                mirrors,
            } => {
                buf.push(0x01);
                buf.extend_from_slice(manifest_hash);
                buf.extend_from_slice(&version_nonce.to_be_bytes());
                buf.extend_from_slice(&(mirrors.len() as u32).to_be_bytes());
                for mirror in mirrors {
                    let bytes = mirror.as_bytes();
                    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                    buf.extend_from_slice(bytes);
                }
            }
            GovernanceAction::LockCouncil => {
                buf.push(0x02);
            }
            GovernanceAction::VetoUpdate { target_hash } => {
                buf.push(0x03);
                buf.extend_from_slice(target_hash);
            }
            GovernanceAction::RotateRootKey { new_key } => {
                buf.push(0x04);
                buf.extend_from_slice(new_key.as_bytes());
            }
            GovernanceAction::RotateGuardKey { new_key } => {
                buf.push(0x05);
                buf.extend_from_slice(new_key.as_bytes());
            }
            GovernanceAction::SelfAppointCouncilMember { candidate_key } => {
                buf.push(0x06);
                buf.extend_from_slice(candidate_key.as_bytes());
            }
            GovernanceAction::RemoveCouncilMember { target_key } => {
                buf.push(0x07);
                buf.extend_from_slice(target_key.as_bytes());
            }
            GovernanceAction::EmergencyReset {
                new_root,
                new_guard,
                override_mode,
            } => {
                buf.push(0x08);
                buf.extend_from_slice(new_root.as_bytes());
                buf.extend_from_slice(new_guard.as_bytes());
                buf.push(if *override_mode { 1 } else { 0 });
            }
            GovernanceAction::ExecuteTimelock { target_hash } => {
                buf.push(0x09);
                buf.extend_from_slice(target_hash);
            }
            GovernanceAction::GrantPremiumName { name, target_pubkey } => {
                buf.push(0x0A);
                let name_bytes = name.as_bytes();
                buf.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
                buf.extend_from_slice(name_bytes);
                buf.extend_from_slice(target_pubkey.as_bytes());
            }
            GovernanceAction::RevokePremiumName { name } => {
                buf.push(0x0B);
                let name_bytes = name.as_bytes();
                buf.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
                buf.extend_from_slice(name_bytes);
            }
        }

        buf.extend_from_slice(&self.council_size_at_proposal.to_be_bytes());
        buf.extend_from_slice(&self.timestamp_sec.to_be_bytes());
        buf
    }
}
