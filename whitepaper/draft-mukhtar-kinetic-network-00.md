---
title: "The Kinetic Network Protocol"
abbrev: "Kinetic Network"
docname: "draft-mukhtar-kinetic-network-00"
date: 2026-06-24
category: info
ipr: trust200902
area: "Internet"
keyword:
  - naming
  - decentralized systems
  - verifiable delay functions
  - service discovery
stand_alone: true
pi:
  toc: "yes"
  sortrefs: "yes"
  symrefs: "yes"

author:
  -
    ins: "S. Mukhtar"
    name: "Saif Mukhtar"
    email: "saifmukhtar20@gmail.com"
    uri: "https://saifmukhtar.dev"

normative:
  RFC2119:
  RFC8174:
  RFC8032:
  RFC8785:

informative:
  RFC8446:
  RFC8610:
  Kademlia:
    title: "Kademlia: A Peer-to-peer Information System Based on the XOR Metric"
    author:
      -
        ins: "P. Maymounkov"
        name: "Petar Maymounkov"
      -
        ins: "D. Mazieres"
        name: "David Mazieres"
    date: "2002"
  Wesolowski:
    title: "Efficient Verifiable Delay Functions"
    author:
      -
        ins: "B. Wesolowski"
        name: "Benjamin Wesolowski"
    date: "2019"
  drand:
    title: "drand: Distributed Randomness Beacon"
    target: "https://drand.love/"
  KineticDocs:
    title: "Kinetic Protocol Official Documentation"
    target: "https://saifmukhtar.github.io/kinetic/"
---

--- abstract

This document specifies the Kinetic Network Protocol, a decentralized naming
and ownership protocol for binding human-readable names to cryptographic
identity keys without a central registry, blockchain, or monetary renewal
system.  Kinetic uses a commit-reveal flow, verifiable delay functions (VDFs),
signed heartbeat records, and redundant Distributed Hash Table (DHT) storage to
make name acquisition sequential, verifiable, and resistant to front-running,
mass registration, and stale-state capture.  This document defines the
protocol model, required records, validation rules, and security
considerations for interoperable Kinetic network implementations.

--- middle

# Introduction

Human-readable names are useful only when users can discover and remember
them.  In open networks, however, a free human-readable namespace is vulnerable
to front-running, dictionary registration, and long-term squatting.  Existing
systems commonly introduce recurring fees, centralized registries, or external
identity verification to control these attacks.

Kinetic takes a different approach.  It treats name ownership as a locally
verifiable cryptographic state.  A registrant proves a name claim by completing
a sequential VDF computation bound to a commitment, an external randomness
beacon value, and the registrant's public key.  Ownership remains live through
signed heartbeat records.  If heartbeats stop, the name becomes increasingly
available for challenge according to deterministic reclamation rules.

Kinetic is not a Domain Name System (DNS) replacement.  It does not directly
map names to addresses.  The network protocol specified here maps a name to an
owner identity key.  Higher-layer documents can define identity documents,
service manifests, content routing, and application semantics.

This Internet-Draft is an individual contribution and is intended to start
discussion on the protocol design, wire formats, threat model, and
interoperability requirements.

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as
shown here.

The following terms are used throughout this document:

Name:
: A human-readable Kinetic name, such as "example.kin".

Owner key:
: A public key that controls a Kinetic name.  This document assumes Ed25519
  {{RFC8032}} unless another signature algorithm is explicitly negotiated by a
  future specification.

Commitment:
: A digest that hides the requested name until the corresponding VDF has been
  computed.

Reveal:
: A signed record that discloses the name, commitment inputs, VDF output, VDF
  proof, and owner key.

Heartbeat:
: A signed freshness assertion from the owner key that keeps the name active.

Lease record:
: The complete verifiable ownership payload for a name, including reveal
  material and the most recent valid heartbeat.

Challenge:
: A VDF-backed attempt to claim an inactive or expired name.

Beacon:
: A publicly verifiable randomness source.  This document uses drand as the
  initial beacon profile.

DHT:
: A Kademlia-like distributed hash table used as an untrusted storage and
  retrieval substrate.

# Protocol Overview

The Kinetic lifecycle has four phases:

1.  Commit: the claimant creates a hidden commitment to the name, beacon round,
    salt, and owner key.

2.  Delay: the claimant evaluates a VDF over the commitment.

3.  Reveal: the claimant publishes a signed lease record containing the VDF
    output and proof.

4.  Maintain: the owner publishes signed heartbeats.  If heartbeats stop, other
    participants can attempt deterministic challenge and reclamation.

The DHT is not trusted to decide ownership.  It only transports records.
Clients and peers decide validity by applying the deterministic validation
rules in this document.

# Cryptographic Primitives

## Hash Function

Implementations MUST use SHA-256 as the default digest algorithm for commitment
construction, DHT key derivation, and record identifiers unless a future
version of this specification defines an algorithm agility mechanism.

All signed structured records MUST be canonicalized before signing.  JSON
encodings MUST use the JSON Canonicalization Scheme (JCS) {{RFC8785}}.

## Signatures

The initial signature profile for Kinetic is Ed25519 {{RFC8032}}.
Implementations conforming to this document MUST support Ed25519 signatures.

Signatures bind the owner key to each reveal, heartbeat, and challenge response.
A record with an invalid signature MUST be rejected and MUST NOT be stored or
forwarded as a valid Kinetic record.

## Randomness Beacon

Kinetic uses an external beacon to prevent precomputation and to provide a
clockless ordering input.  The initial beacon profile is drand {{drand}}.

Implementations MUST verify beacon signatures before accepting a beacon round
as an input to a commitment or heartbeat.  Implementations MUST reject records
that reference unavailable, malformed, or unverifiable beacon data.

## Verifiable Delay Function

Kinetic requires a VDF with the following properties:

* Evaluation requires a configured number of sequential steps.
* Verification is substantially faster than evaluation.
* The proof binds the output to the input and difficulty parameter.
* Parallel hardware does not substantially reduce wall-clock evaluation time
  for a single challenge.

The initial VDF construction is based on repeated squaring in a group of
unknown order with a Wesolowski-style proof {{Wesolowski}}.  A future revision
of this document is expected to define an exact VDF ciphersuite registry.

# Name Registration

## Commitment Construction

To register a name, the claimant first obtains a valid beacon value for round
`r1` and generates a salt with at least 256 bits of entropy.

The claimant computes:

~~~
commitment = SHA256("KINETIC-COMMIT-v1" ||
                    name ||
                    salt ||
                    beacon_round ||
                    beacon_randomness ||
                    owner_public_key)
~~~

The domain separation string is REQUIRED.  Implementations MUST NOT reuse this
commitment construction for unrelated protocol purposes.

The claimant uses the commitment as the VDF input.  The VDF difficulty is
derived from the name and the active network parameter set.

## Difficulty Function

The VDF difficulty function is intended to make short, high-value names more
expensive to claim than longer names while preserving deterministic validation.

This version defines the following abstract interface:

~~~
difficulty = Difficulty(name, beacon_round, parameter_set)
~~~

All validators MUST compute the same difficulty for a given name, beacon round,
and parameter set.  A future revision of this document MUST define exact
constants before this protocol can be considered stable for deployment.

## Reveal Record

After the VDF completes, the claimant publishes a reveal record:

~~~ json
{
  "type": "kinetic.reveal.v1",
  "name": "example.kin",
  "salt": "base64url...",
  "beacon_round": 1234567,
  "beacon_randomness": "base64url...",
  "owner_public_key": "ed25519:base64url...",
  "vdf": {
    "suite": "vdf-wesolowski-classgroup-v1",
    "difficulty": 10000000,
    "input": "base64url...",
    "output": "base64url...",
    "proof": "base64url..."
  },
  "signature": "base64url..."
}
~~~

The signature covers the canonicalized reveal record with the `signature`
member omitted.

A validator MUST reject a reveal record unless all of the following are true:

* The name is syntactically valid.
* The beacon round and beacon randomness are valid.
* The commitment recomputed from the record fields equals the VDF input.
* The VDF proof verifies for the input, output, suite, and difficulty.
* The difficulty equals the deterministic difficulty for the name and round.
* The signature verifies under the owner public key.

# Heartbeats and Liveness

An active owner maintains a name by publishing heartbeat records.  A heartbeat
is a signed statement over the name, owner key, current beacon round, and a
monotonic nonce.

~~~ json
{
  "type": "kinetic.heartbeat.v1",
  "name": "example.kin",
  "owner_public_key": "ed25519:base64url...",
  "beacon_round": 1234600,
  "nonce": 42,
  "signature": "base64url..."
}
~~~

A validator MUST reject a heartbeat unless:

* The signature verifies under the current owner key.
* The heartbeat name matches the associated lease record.
* The beacon round is valid and not older than the previous accepted heartbeat
  for the same lease record.
* The nonce is greater than the previous accepted nonce for the same lease
  record.

This document does not require a heartbeat every beacon round.  Exact heartbeat
intervals are deployment parameters and MUST be included in the active
parameter set.

# Reclamation and Challenges

If a valid heartbeat has not been observed for a name within the configured
active interval, the name becomes inactive.  Inactive names can be challenged by
computing a challenge VDF whose difficulty is derived from the elapsed beacon
rounds since the last valid heartbeat.

The challenge difficulty function has the abstract form:

~~~
challenge_difficulty =
  ChallengeDifficulty(name, last_heartbeat_round, current_round, parameter_set)
~~~

The function SHOULD make very recent inactive names expensive to challenge and
older inactive names less expensive to reclaim.  The function MUST be
deterministic.

A successful challenge does not by itself prove that the old owner has lost the
name.  A deployment MAY define a challenge response window during which the
previous owner can publish a fresh heartbeat to invalidate the challenge.

# DHT Storage and Retrieval

Kinetic uses a DHT as an untrusted data transport.  A node receiving a Kinetic
record MUST validate the record before storing or forwarding it as a valid
record.

To reduce single-key censorship risk, a lease record SHOULD be stored at
multiple deterministic keys:

~~~
dht_key_i = SHA256("KINETIC-DHT-v1" || name || i)
~~~

where `i` is an integer in the range `0..M-1`.  The replication count `M` is a
deployment parameter.  Clients SHOULD query multiple keys and take the union of
returned records before applying local validation and selection.

# Record Selection

When a client obtains multiple valid lease records for the same name, it MUST
select a single winning record deterministically.

This document defines the following provisional ordering:

1.  Prefer the valid record with the earliest beacon round used in the initial
    reveal.

2.  If two records use the same reveal beacon round, prefer the record whose
    VDF output has the smallest XOR distance to the next valid beacon
    randomness value after the reveal round.

3.  If records remain tied, prefer the lexicographically smallest canonical
    record digest.

This ordering is intended to remove network latency as a deciding factor.  A
future version of this document should analyze whether earliest-round
selection creates undesirable long-range behavior and whether checkpointing or
bounded history rules are needed.

# Light Client Resolution

A light client need not participate in the DHT.  It MAY obtain records from one
or more untrusted HTTPS gateways.  Gateways are data transports only.  They do
not decide ownership and need not be trusted.

A light client resolving a name SHOULD:

1.  Query at least three independently operated gateways.
2.  Request records for all deterministic DHT keys for the target name.
3.  Validate all returned records locally.
4.  Apply the deterministic record selection algorithm.
5.  Return the selected owner key or report that no valid record was found.

A gateway can censor by omission, but it cannot forge valid records without the
owner key and VDF proof.  Querying multiple independent gateways reduces
omission risk.

# Parameter Sets

Kinetic deployments require shared parameters, including:

* name syntax rules;
* VDF ciphersuite;
* registration difficulty function;
* challenge difficulty function;
* heartbeat interval;
* challenge response window;
* DHT replication count; and
* accepted beacon network identifiers.

This draft intentionally marks the concrete parameter set as provisional.
Interoperable public deployments MUST NOT claim conformance to a final Kinetic
profile until these parameters are fully specified.

# IANA Considerations

This document has no IANA actions.

A future version might request registries for Kinetic record types, VDF suites,
signature suites, beacon profiles, and well-known service identifiers.

# Security Considerations

Kinetic assumes that adversaries can observe, delay, replay, omit, and inject
DHT traffic.  Correct implementations MUST treat the network and gateways as
untrusted.

Commitments are intended to prevent front-running.  The beacon value prevents
precomputation before the referenced round.  Binding the owner key into the
commitment prevents a third party from reusing another claimant's completed VDF
under a different key.

The VDF difficulty is the primary Sybil-resistance mechanism.  If the VDF is
parallelizable, incorrectly parameterized, or too cheap for the target
deployment, attackers can register names at scale.  Public deployments require
empirical calibration, independent cryptographic review, and a clear upgrade
story.

The DHT can be attacked through eclipse, spam, storage exhaustion, and
censorship by omission.  Implementations SHOULD validate before storing,
replicate records across deterministic independent keys, rate-limit invalid
traffic, and avoid treating any single gateway or peer as authoritative.

Heartbeat loss can occur for benign reasons such as device failure, key loss,
network partition, or long-term offline use.  Challenge parameters that are too
aggressive can cause accidental loss of names.  Parameters that are too lenient
can preserve abandoned names indefinitely.

Private keys control names.  A compromised owner key allows an attacker to
publish valid heartbeats and update higher-layer identity bindings.  Users need
secure key storage and recovery mechanisms.  Those recovery mechanisms are out
of scope for this document.

Beacon dependence creates availability and governance questions.  If the
configured beacon becomes unavailable or distrusted, implementations need a
deterministic transition path.  This draft does not yet specify that path.

# Privacy Considerations

Kinetic records are public.  Heartbeat cadence can reveal that an owner is
online or offline.  Gateway queries can reveal user interest in specific names.
Clients concerned with privacy should query multiple names together, use
privacy-preserving transports where available, and avoid sending identifying
metadata to gateways.

# Operational Considerations

Operators of gateways and DHT nodes should expect invalid traffic.  They should
apply strict parsing, bounded memory use, record-size limits, signature
verification before storage, and per-peer rate limits.

Implementations should expose clear diagnostics for VDF verification failures,
beacon verification failures, stale heartbeats, and conflicting lease records.

--- back

# Acknowledgements

The protocol design discussed in this document draws on prior work in
Kademlia-style routing, verifiable delay functions, threshold randomness, and
self-authenticating records.
