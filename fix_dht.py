import re

with open("kinetic-core/src/error/dht.rs", "r") as f:
    content = f.read()

# Revert the derive for ResolutionError
content = re.sub(
    r"(\/\/\/ Errors during DHT name resolution.*?\n)#\[derive\(Error, Debug, PartialEq, Eq\)\]\npub enum ResolutionError",
    r"\1#[derive(Error, Debug)]\npub enum ResolutionError",
    content,
    flags=re.DOTALL
)

# Revert the derive for PublishError
content = re.sub(
    r"(\/\/\/ Errors when publishing records to the DHT.*?\n)#\[derive\(Error, Debug, PartialEq, Eq\)\]\npub enum PublishError",
    r"\1#[derive(Error, Debug)]\npub enum PublishError",
    content,
    flags=re.DOTALL
)

# Revert the derive for RegistrationError
content = re.sub(
    r"(\/\/\/ Errors during \.kin name registration flow.*?\n)#\[derive\(Error, Debug, PartialEq, Eq\)\]\npub enum RegistrationError",
    r"\1#[derive(Error, Debug)]\npub enum RegistrationError",
    content,
    flags=re.DOTALL
)

# Note: RecordRejectReason does not have source: Box<dyn Error>, so it can keep #[derive(PartialEq, Eq)]

impls = """
impl PartialEq for ResolutionError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Offline, Self::Offline) => true,
            (Self::NotFound { name: a_n, peers_queried: a_p }, Self::NotFound { name: b_n, peers_queried: b_p }) => a_n == b_n && a_p == b_p,
            (Self::VdfVerificationFailed { name: a_n, count: a_c }, Self::VdfVerificationFailed { name: b_n, count: b_c }) => a_n == b_n && a_c == b_c,
            (Self::Expired { name: a_n, age: a_a }, Self::Expired { name: b_n, age: b_a }) => a_n == b_n && a_a == b_a,
            (Self::Timeout { name: a_n, elapsed_ms: a_e, peers_queried: a_p }, Self::Timeout { name: b_n, elapsed_ms: b_e, peers_queried: b_p }) => a_n == b_n && a_e == b_e && a_p == b_p,
            (Self::Internal { message: a_m, .. }, Self::Internal { message: b_m, .. }) => a_m == b_m,
            _ => false,
        }
    }
}
impl Eq for ResolutionError {}

impl PartialEq for PublishError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Offline, Self::Offline) => true,
            (Self::InvalidProof(a), Self::InvalidProof(b)) => a == b,
            (Self::AlreadyOwned { name: a_n }, Self::AlreadyOwned { name: b_n }) => a_n == b_n,
            (Self::AllFailed { count: a_c }, Self::AllFailed { count: b_c }) => a_c == b_c,
            (Self::Internal { message: a_m, .. }, Self::Internal { message: b_m, .. }) => a_m == b_m,
            _ => false,
        }
    }
}
impl Eq for PublishError {}

impl PartialEq for RegistrationError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::InvalidName { name: a_n }, Self::InvalidName { name: b_n }) => a_n == b_n,
            (Self::VdfFailed(a), Self::VdfFailed(b)) => a == b,
            (Self::CommitmentMismatch, Self::CommitmentMismatch) => true,
            (Self::AlreadyOwned { name: a_n }, Self::AlreadyOwned { name: b_n }) => a_n == b_n,
            (Self::AlreadyInProgress { name: a_n }, Self::AlreadyInProgress { name: b_n }) => a_n == b_n,
            (Self::NetworkRejected { reason: a_r }, Self::NetworkRejected { reason: b_r }) => a_r == b_r,
            (Self::Internal { message: a_m, .. }, Self::Internal { message: b_m, .. }) => a_m == b_m,
            _ => false,
        }
    }
}
impl Eq for RegistrationError {}
"""

with open("kinetic-core/src/error/dht.rs", "a") as f:
    f.write(impls)

