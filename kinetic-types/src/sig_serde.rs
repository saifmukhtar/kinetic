//! Serialization adapters for strictly-typed ML-DSA-65 signatures.
//!
//! Enforces parse-time constraints on cryptographic signatures. The post-quantum
//! ML-DSA-65 signatures must be exactly 3309 bytes long. If the byte payload is
//! any other length, this adapter will instantly reject it during deserialization,
//! preventing oversized or malformed payloads from entering the network logic.

macro_rules! impl_sig_serde {
    ($mod_name:ident, $sig_type:ident) => {
        pub mod $mod_name {
            use kinetic_primitives::KINETIC_SIGNATURE_LENGTH;
            use kinetic_primitives::keypairs::$sig_type;
            use serde::{Deserialize, Deserializer, Serialize, Serializer};

            pub fn serialize<S: Serializer>(sig: &$sig_type, s: S) -> Result<S::Ok, S::Error> {
                sig.0.serialize(s)
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<$sig_type, D::Error> {
                let bytes = std::vec::Vec::<u8>::deserialize(d)?;
                if bytes.len() != KINETIC_SIGNATURE_LENGTH {
                    return Err(serde::de::Error::custom(format!(
                        "Invalid ML-DSA-65 signature length: expected {}, got {}",
                        KINETIC_SIGNATURE_LENGTH,
                        bytes.len()
                    )));
                }
                Ok($sig_type(bytes))
            }
        }
    };
}

macro_rules! impl_vec_sig_serde {
    ($mod_name:ident, $sig_type:ident) => {
        pub mod $mod_name {
            use kinetic_primitives::KINETIC_SIGNATURE_LENGTH;
            use kinetic_primitives::keypairs::$sig_type;
            use serde::{Deserialize, Deserializer, Serialize, Serializer};

            pub fn serialize<S: Serializer>(
                sigs: &std::vec::Vec<$sig_type>,
                s: S,
            ) -> Result<S::Ok, S::Error> {
                let raw: std::vec::Vec<&std::vec::Vec<u8>> =
                    sigs.iter().map(|sig| &sig.0).collect();
                raw.serialize(s)
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(
                d: D,
            ) -> Result<std::vec::Vec<$sig_type>, D::Error> {
                let raw = std::vec::Vec::<std::vec::Vec<u8>>::deserialize(d)?;
                let mut sigs = std::vec::Vec::with_capacity(raw.len());
                for bytes in raw {
                    if bytes.len() != KINETIC_SIGNATURE_LENGTH {
                        return Err(serde::de::Error::custom(format!(
                            "Invalid ML-DSA-65 signature length: expected {}, got {}",
                            KINETIC_SIGNATURE_LENGTH,
                            bytes.len()
                        )));
                    }
                    sigs.push($sig_type(bytes));
                }
                Ok(sigs)
            }
        }
    };
}

impl_sig_serde!(identity_sig_serde, IdentitySignature);
impl_sig_serde!(controller_sig_serde, ControllerSignature);
impl_sig_serde!(revoke_sig_serde, RevokeSignature);
impl_sig_serde!(delegated_sig_serde, DelegatedSignature);
impl_sig_serde!(sovereign_sig_serde, SovereignSignature);

impl_vec_sig_serde!(vec_identity_sig_serde, IdentitySignature);
impl_vec_sig_serde!(vec_controller_sig_serde, ControllerSignature);
impl_vec_sig_serde!(vec_revoke_sig_serde, RevokeSignature);
impl_vec_sig_serde!(vec_delegated_sig_serde, DelegatedSignature);
impl_vec_sig_serde!(vec_sovereign_sig_serde, SovereignSignature);

#[cfg(test)]
mod tests {
    use super::*;
    use kinetic_primitives::KINETIC_SIGNATURE_LENGTH;
    use kinetic_primitives::keypairs::IdentitySignature;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct TestContainer {
        #[serde(with = "identity_sig_serde")]
        sig: IdentitySignature,
    }

    #[test]
    fn test_valid_length_deserializes() {
        let valid_bytes = vec![0u8; KINETIC_SIGNATURE_LENGTH];
        let json = serde_json::json!({ "sig": valid_bytes }).to_string();

        let parsed: Result<TestContainer, _> = serde_json::from_str(&json);
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_invalid_length_fails() {
        let invalid_bytes = vec![0u8; 5];
        let json = serde_json::json!({ "sig": invalid_bytes }).to_string();

        let parsed: Result<TestContainer, _> = serde_json::from_str(&json);
        assert!(parsed.is_err());
        let err_msg = parsed.unwrap_err().to_string();
        assert!(err_msg.contains("Invalid ML-DSA-65 signature length"));
    }
}
