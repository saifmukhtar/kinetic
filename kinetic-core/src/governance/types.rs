use ml_dsa::signature::Verifier;
use ml_dsa::KeyInit;
use ml_dsa::MlDsa65;
use std::collections::{HashMap, HashSet};

pub type Hash256 = [u8; 32];
pub type PublicKeyBytes = Vec<u8>;
pub type SignatureBytes = Vec<u8>;

pub fn verify_signature(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if let Ok(pk) = ml_dsa::VerifyingKey::<MlDsa65>::new_from_slice(pubkey) {
        if let Ok(signature) = ml_dsa::Signature::<MlDsa65>::try_from(sig) {
            return pk.verify(msg, &signature).is_ok();
        }
    }
    false
}

/// Enumerates the possible actions that can be taken by the governance system.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum GovernanceAction {
    AppointMember {
        key: PublicKeyBytes,
    },
    UpdateBinary {
        manifest_hash: Hash256,
        version_nonce: u64,
        github_username: String,
        git_commit: String,
        git_branch: String,
        mirrors: Vec<String>,
    },
    LockCouncil,
    VetoUpdate {
        target_hash: Hash256,
    },
    RotateRootKey {
        new_key: PublicKeyBytes,
    },
    RotateGuardKey {
        new_key: PublicKeyBytes,
    },
    SelfAppointCouncilMember {
        candidate_key: PublicKeyBytes,
    },
    RemoveCouncilMember {
        target_key: PublicKeyBytes,
    },

    ExecuteTimelock {
        target_hash: Hash256,
    },
    GrantPremiumName {
        name: String,
        target_pubkey: PublicKeyBytes,
    },
    RevokePremiumName {
        name: String,
    },
}

/// Represents the side effects or outcomes of executing a governance action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceEffect {
    TriggerOTA {
        manifest_hash: Hash256,
        mirrors: Vec<String>,
    },
    PremiumNameGranted {
        name: String,
        target_pubkey: PublicKeyBytes,
    },
    PremiumNameRevoked {
        name: String,
    },
}

/// Indicates the current phase or mode of the governance system (e.g., Founder phase vs Council phase).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GovernanceMode {
    Founder,
    Council,
}

/// Represents a governance message that has been signed by one or more authorized keys.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedGovernanceMessage {
    pub action: GovernanceAction,
    pub council_size_at_proposal: u32,
    pub timestamp_sec: u64,
    pub signatures: Vec<SignatureBytes>,
}

/// Maintains the current state of the governance system, including active council members and pending actions.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GovernanceState {
    pub genesis_timestamp_sec: u64,
    pub mode: GovernanceMode,
    pub lock_timestamp_sec: Option<u64>,
    pub active_council: Vec<PublicKeyBytes>,
    pub last_signature_timestamps: HashMap<PublicKeyBytes, u64>,

    pub vetoed_hashes: HashSet<Hash256>,
    pub pending_updates: HashMap<Hash256, (u64, u64, Vec<String>)>,
    pub partial_proposals: HashMap<Hash256, SignedGovernanceMessage>,
    pub founder_premium_grants: u8,
    pub grace_period_start_sec: Option<u64>,
    #[serde(default)]
    pub dynamic_root_key: Option<PublicKeyBytes>,
    #[serde(default)]
    pub dynamic_guard_key: Option<PublicKeyBytes>,
}

impl SignedGovernanceMessage {
    /// Serializes the governance message into a canonical byte vector for hashing and signature verification.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match &self.action {
            GovernanceAction::AppointMember { key } => {
                buf.push(0x00);
                buf.extend_from_slice(key.as_slice());
            }
            GovernanceAction::UpdateBinary {
                manifest_hash,
                version_nonce,
                github_username,
                git_commit,
                git_branch,
                mirrors,
            } => {
                buf.push(0x01);
                buf.extend_from_slice(manifest_hash);
                buf.extend_from_slice(&version_nonce.to_be_bytes());
                buf.extend_from_slice(&(github_username.len() as u32).to_be_bytes());
                buf.extend_from_slice(github_username.as_bytes());
                buf.extend_from_slice(&(git_commit.len() as u32).to_be_bytes());
                buf.extend_from_slice(git_commit.as_bytes());
                buf.extend_from_slice(&(git_branch.len() as u32).to_be_bytes());
                buf.extend_from_slice(git_branch.as_bytes());
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
                buf.extend_from_slice(new_key.as_slice());
            }
            GovernanceAction::RotateGuardKey { new_key } => {
                buf.push(0x05);
                buf.extend_from_slice(new_key.as_slice());
            }
            GovernanceAction::SelfAppointCouncilMember { candidate_key } => {
                buf.push(0x06);
                buf.extend_from_slice(candidate_key.as_slice());
            }
            GovernanceAction::RemoveCouncilMember { target_key } => {
                buf.push(0x07);
                buf.extend_from_slice(target_key.as_slice());
            }

            GovernanceAction::ExecuteTimelock { target_hash } => {
                buf.push(0x09);
                buf.extend_from_slice(target_hash);
            }
            GovernanceAction::GrantPremiumName {
                name,
                target_pubkey,
            } => {
                buf.push(0x0A);
                let name_bytes = name.as_bytes();
                buf.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
                buf.extend_from_slice(name_bytes);
                buf.extend_from_slice(target_pubkey.as_slice());
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
