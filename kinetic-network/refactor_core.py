import re

with open("src/store/core.rs", "r") as f:
    content = f.read()

# Remove verify_reveal_internal
content = re.sub(r"    pub\(crate\) fn verify_reveal_internal\(&self, reveal: &kinetic_core::types::Reveal\) -> bool \{.*?\n    \}\n", "", content, flags=re.DOTALL)

# Update AuthorizedKid logic
kid_old = """        } else if let Ok(auth_kid) =
            serde_json::from_slice::<kinetic_core::types::AuthorizedKid>(&r.value)
        {
            if let Some(reveal) = self.reveals_by_name.get(&auth_kid.name) {
                if let Ok(pubkey) = ed25519_dalek::VerifyingKey::try_from(reveal.pubkey.as_slice())
                {
                    use ed25519_dalek::Verifier;
                    if let Ok(sig) = ed25519_dalek::Signature::from_slice(&auth_kid.owner_signature)
                    {
                        if pubkey.verify(&auth_kid.signable_bytes(), &sig).is_ok()
                            && auth_kid.kid_doc.verify().is_ok()
                        {
                            tracing::info!(
                                "KineticRecordStore::put accepted AuthorizedKid for {}",
                                auth_kid.kid_doc.kid.as_str()
                            );
                        } else {
                            let err = KineticStoreError::InvalidKidSignature;
                            tracing::warn!(
                                error_code = "KIN-STORE-017",
                                severity = ?err.severity(),
                                "Rejecting AuthorizedKid: invalid signature or invalid document"
                            );
                            return Err(err.into());
                        }
                    } else {
                        return Err(KineticStoreError::InvalidKidSignature.into());
                    }
                } else {
                    return Err(KineticStoreError::InvalidKidSignature.into());
                }
            } else {
                tracing::warn!(
                    "Rejecting AuthorizedKid: No active reveal found for name {}",
                    auth_kid.name
                );
                return Err(KineticStoreError::InvalidKidSignature.into());
            }
        }"""
kid_new = """        } else if let Ok(auth_kid) =
            serde_json::from_slice::<kinetic_core::types::AuthorizedKid>(&r.value)
        {
            let active_reveal = self.reveals_by_name.get(&auth_kid.name);
            if let Err(e) = super::verification::verify_authorized_kid(&auth_kid, active_reveal) {
                return Err(e.into());
            }
        }"""
content = content.replace(kid_old, kid_new)

# Update AuthorizedManifest logic
man_old = """ else if let Ok(auth_manifest) =
            serde_json::from_slice::<kinetic_core::types::AuthorizedManifest>(&r.value)
        {
            if let Some(reveal) = self.reveals_by_name.get(&auth_manifest.name) {
                if let Ok(pubkey) = ed25519_dalek::VerifyingKey::try_from(reveal.pubkey.as_slice())
                {
                    use ed25519_dalek::Verifier;
                    if let Ok(sig) =
                        ed25519_dalek::Signature::from_slice(&auth_manifest.owner_signature)
                    {
                        if pubkey.verify(&auth_manifest.signable_bytes(), &sig).is_ok() {
                            tracing::info!(
                                "KineticRecordStore::put accepted AuthorizedManifest for {}",
                                auth_manifest.manifest.kid.as_str()
                            );
                        } else {
                            let err = KineticStoreError::InvalidManifestSignature;
                            tracing::warn!(
                                error_code = "KIN-STORE-018",
                                severity = ?err.severity(),
                                "Rejecting AuthorizedManifest: invalid signature"
                            );
                            return Err(err.into());
                        }
                    } else {
                        return Err(KineticStoreError::InvalidManifestSignature.into());
                    }
                } else {
                    return Err(KineticStoreError::InvalidManifestSignature.into());
                }
            } else {
                tracing::warn!(
                    "Rejecting AuthorizedManifest: No active reveal found for name {}",
                    auth_manifest.name
                );
                return Err(KineticStoreError::InvalidManifestSignature.into());
            }
        }"""
man_new = """ else if let Ok(auth_manifest) =
            serde_json::from_slice::<kinetic_core::types::AuthorizedManifest>(&r.value)
        {
            let active_reveal = self.reveals_by_name.get(&auth_manifest.name);
            if let Err(e) = super::verification::verify_authorized_manifest(&auth_manifest, active_reveal) {
                return Err(e.into());
            }
        }"""
content = content.replace(man_old, man_new)

with open("src/store/core.rs", "w") as f:
    f.write(content)

