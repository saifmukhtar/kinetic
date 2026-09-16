//! Serialization adapters for Layer 1 public keys.
//!
//! This module provides `serde` adapters for the strict taxonomy keys defined in `kinetic-primitives`.
//! We use a custom adapter pattern here to keep `serde` strictly out of Layer 1, preventing the accidental
//! serialization of private keys.

use kinetic_primitives::kinetic_keypair::{
    ControllerPubKey, DelegatedPubKey, IdentityPubKey, RevokePubKey, SovereignPubKey,
};

macro_rules! impl_pubkey_serde {
    ($mod_name:ident, $key_type:ident) => {
        pub mod $mod_name {
            use super::$key_type;
            use serde::{Deserialize, Deserializer, Serialize, Serializer};

            pub fn serialize<S: Serializer>(key: &$key_type, s: S) -> Result<S::Ok, S::Error> {
                key.0.serialize(s)
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<$key_type, D::Error> {
                let bytes = std::vec::Vec::<u8>::deserialize(d)?;
                Ok($key_type(bytes))
            }
        }
    };
}

impl_pubkey_serde!(identity_serde, IdentityPubKey);
impl_pubkey_serde!(controller_serde, ControllerPubKey);
impl_pubkey_serde!(revoke_serde, RevokePubKey);
impl_pubkey_serde!(delegated_serde, DelegatedPubKey);
impl_pubkey_serde!(sovereign_serde, SovereignPubKey);
