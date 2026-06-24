---
title: "Kinetic Identity Documents and Service Manifests"
abbrev: "Kinetic Identity"
docname: "draft-mukhtar-kinetic-identity-00"
date: 2026-06-24
category: info
ipr: trust200902
area: "Internet"
keyword:
  - identity
  - service discovery
  - decentralized naming
  - manifests
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
  RFC3986:
  RFC8259:

informative:
  I-D.mukhtar-kinetic-network:
    title: "The Kinetic Network Protocol"
    author:
      -
        ins: "S. Mukhtar"
        name: "Saif Mukhtar"
    date: "2026"
  DID-CORE:
    title: "Decentralized Identifiers (DIDs) v1.0"
    author:
      -
        org: "W3C"
    target: "https://www.w3.org/TR/did-core/"
  KineticDocs:
    title: "Kinetic Protocol Official Documentation"
    target: "https://saifmukhtar.github.io/kinetic/"
---

--- abstract

This document specifies Kinetic Identity Documents (KIDs) and Capability
Manifests, a higher-layer identity and service-discovery model for the Kinetic
Network Protocol.  A Kinetic name is a transferable human-readable alias.  A
KID is a persistent cryptographic identity.  A Capability Manifest, signed by
the KID, describes the services currently offered by that identity.  This
separation prevents applications from confusing a name with an identity and
allows names to resolve to websites, APIs, messaging endpoints, storage
systems, agents, and future services without changing the underlying naming
protocol.

--- middle

# Introduction

Traditional name resolution usually asks one question: what network location
corresponds to this name?  Modern networked entities often need a richer answer.
An identity may expose a website, an API, a storage endpoint, a messaging
endpoint, an application service, or a future service type that does not map
cleanly to one host address.

Kinetic separates these concerns into layers:

1.  Human-readable name.
2.  Persistent cryptographic identity.
3.  Signed capability manifest.
4.  Application-specific content or compute.

The Kinetic Network Protocol {{I-D.mukhtar-kinetic-network}} defines how a
human-readable name is claimed, maintained, and resolved to an owner key.  This
document defines how that owner key is used as a persistent identity anchor and
how applications discover services associated with that identity.

This document is an individual contribution and is intended to start discussion
on a Kinetic identity and service-discovery profile.

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as
shown here.

The following terms are used throughout this document:

Kinetic name:
: A human-readable alias controlled through the Kinetic Network Protocol.

KID:
: A Kinetic Identity Document identifier and the associated signed document.

Subject:
: The entity represented by a KID.

Capability Manifest:
: A signed document that lists services currently offered by a KID subject.

Service:
: An application-level endpoint, protocol, content root, or capability exposed
  by the subject.

Controller key:
: A public key authorized to sign KID updates or manifests.

# Design Goals

The Kinetic identity layer has the following goals:

* Separate human-readable names from persistent identities.
* Allow name ownership to change without silently transferring identity trust.
* Allow one identity to advertise multiple services.
* Allow service types to evolve without changing the base naming protocol.
* Permit light clients to verify identity and manifest data locally.
* Avoid requiring clients to trust gateways or DHT nodes.

# Name and Identity Separation

A Kinetic name is transferable.  A KID is persistent and non-transferable.

If "example.kin" points to Alice's KID today and Bob's KID tomorrow, clients
MUST treat that as an identity change.  Applications MUST NOT assume continuity
of identity from continuity of name alone.

This distinction is intended to prevent semantic attacks where a user sends
encrypted messages, authorization decisions, payments, or other sensitive
actions to a name after that name has changed owners.

# KID Identifier Syntax

A KID identifier has the following URI form:

~~~
did:kin:<method-specific-id>
~~~

The `did:kin` prefix follows the DID URI style defined by {{DID-CORE}}, but
this document does not register a DID method.  Formal DID method registration
is out of scope for this version.

The `method-specific-id` MUST be derived from the subject's primary public key
or a collision-resistant digest of the initial KID document.  The exact
derivation is a profile parameter and MUST be specified before production
interoperability.

KID identifiers MUST be valid URIs {{RFC3986}}.

# KID Document

A KID document is a canonical JSON document {{RFC8259}} signed by one or more
authorized controller keys.

An example KID document is shown below:

~~~ json
{
  "type": "kinetic.kid.v1",
  "kid": "did:kin:kid1abc9f7",
  "created_at": 1750000000,
  "controller_keys": [
    {
      "id": "did:kin:kid1abc9f7#primary",
      "type": "Ed25519",
      "public_key": "base64url..."
    }
  ],
  "manifest": {
    "hash": "sha256:base64url...",
    "locations": [
      "kinetic-dht:base64url...",
      "https://gateway.example/kinetic/manifests/base64url..."
    ]
  },
  "revocation_keys": [
    "ed25519:base64url..."
  ],
  "signature": "base64url..."
}
~~~

The signature covers the canonicalized KID document with the `signature` member
omitted.  JSON encodings used for signatures MUST be canonicalized with JCS
{{RFC8785}}.

## Required Members

A KID document MUST contain:

* `type`, with value `kinetic.kid.v1`;
* `kid`, containing the KID identifier;
* `controller_keys`, containing at least one supported public key;
* `manifest`, containing either a manifest hash, one or more manifest
  locations, or both; and
* `signature`, containing a signature by an authorized controller key.

## Controller Keys

Implementations conforming to this document MUST support Ed25519 {{RFC8032}}.

A KID document MAY contain multiple controller keys.  Applications SHOULD allow
key rotation, but MUST verify that any updated KID document is authorized by a
valid previous controller key or by a valid recovery mechanism defined by the
active profile.

This draft does not fully specify recovery or rotation semantics.  Production
profiles MUST define them before relying on KID continuity for sensitive use
cases.

# Capability Manifest

A Capability Manifest describes services currently offered by a KID subject.
The manifest is mutable and signed by a controller key authorized by the KID
document.

An example manifest is shown below:

~~~ json
{
  "type": "kinetic.manifest.v1",
  "kid": "did:kin:kid1abc9f7",
  "version": 7,
  "valid_from": 1750000000,
  "services": [
    {
      "id": "web",
      "type": "website",
      "protocol": "https",
      "endpoint": "https://www.example.net/"
    },
    {
      "id": "api",
      "type": "api",
      "protocol": "grpc",
      "endpoint": "api.example.net:443"
    },
    {
      "id": "messages",
      "type": "messaging",
      "protocol": "wss",
      "endpoint": "wss://relay.example.net/"
    }
  ],
  "signature": "base64url..."
}
~~~

The signature covers the canonicalized manifest with the `signature` member
omitted.

## Required Members

A Capability Manifest MUST contain:

* `type`, with value `kinetic.manifest.v1`;
* `kid`, matching the KID document subject;
* `version`, a monotonically increasing integer;
* `services`, an array of service entries; and
* `signature`, a signature by an authorized KID controller key.

## Service Entries

Each service entry MUST contain:

* `id`, unique within the manifest;
* `type`, identifying the service class;
* `protocol`, identifying the application or transport protocol; and
* `endpoint`, containing the protocol-specific endpoint or content reference.

Service entries MAY include additional protocol-specific fields.  Unknown fields
MUST be ignored unless the service type explicitly requires rejection.

# Resolution Flow

A client resolving a Kinetic name to a service performs the following steps:

1.  Resolve the Kinetic name using the Kinetic Network Protocol.
2.  Obtain the owner key or KID binding from the selected lease record.
3.  Fetch the KID document from the DHT, gateway, or another advertised
    location.
4.  Verify the KID document signature.
5.  Fetch the Capability Manifest referenced by the KID document.
6.  Verify the manifest hash, if present.
7.  Verify the manifest signature under an authorized KID controller key.
8.  Select a service entry matching the desired service type and protocol.

All fetched data is untrusted until locally verified.  A gateway or DHT node
MUST NOT be treated as authoritative.

# Name-to-KID Binding

The selected Kinetic lease record MUST bind the name to a KID identifier or to
the public key from which the KID identifier can be derived.

For the initial profile, the lease record SHOULD include:

~~~ json
{
  "kid": "did:kin:kid1abc9f7",
  "kid_document_hash": "sha256:base64url..."
}
~~~

The KID document hash helps clients detect gateway omission or downgrade
attacks.  If the hash is present, clients MUST reject any fetched KID document
whose canonical digest does not match the lease record.

# Updates and Versioning

KID documents and manifests use different mutability rules.

A KID document is intended to be stable.  Updates SHOULD be rare and limited to
key rotation, recovery, manifest pointer updates, and revocation metadata.

A Capability Manifest is expected to change as services are added, removed, or
moved.  Manifest versions MUST be monotonically increasing for a given KID.
Clients SHOULD prefer the highest valid version unless an application profile
defines stricter freshness requirements.

Clients SHOULD cache verified KID documents and manifests, but MUST respect
application-specific freshness and revocation requirements.

# Service Type Extensibility

This document defines the manifest container but does not define a complete
service-type registry.

Common service type values might include:

* `website`;
* `api`;
* `messaging`;
* `storage`;
* `agent`;
* `payment`; and
* `profile`.

A future version of this document might request an IANA registry for Kinetic
service types and protocol identifiers.

# IANA Considerations

This document has no IANA actions.

A future version might request registries for KID document versions, manifest
versions, controller key suites, service types, and service protocol
identifiers.

# Security Considerations

Applications MUST NOT treat a human-readable Kinetic name as a stable identity.
Names can be transferred or reclaimed.  Identity continuity depends on the KID,
not on the name.

KID and manifest verification depends on canonicalization.  Inconsistent JSON
canonicalization can create signature bypasses or interoperability failures.
Implementations MUST sign and verify the exact canonical form defined by the
active profile.

Controller key compromise allows an attacker to publish malicious manifests,
redirect services, or rotate identity metadata.  Sensitive applications need
key isolation, recovery procedures, revocation checking, and user-visible
identity-change warnings.

Manifest endpoints can point to malicious services.  Kinetic verification only
proves that a controller key advertised the endpoint.  It does not prove that
the endpoint is safe, lawful, available, or operated by a trustworthy party.

Gateways and DHT nodes can omit or replay older documents.  Clients SHOULD use
hash bindings from lease records, manifest versions, multiple retrieval paths,
and freshness checks to reduce downgrade and censorship risks.

Service identifiers can create confusion if different applications interpret
the same service type differently.  Future profiles should define precise
semantics for service types used in security-sensitive contexts.

# Privacy Considerations

Capability Manifests can reveal relationships between names, identities, and
services.  Publishing a manifest may expose operational infrastructure, user
aliases, contact endpoints, or organizational structure.

Clients querying gateways for KID documents or manifests can reveal which
identities or services they are interested in.  Privacy-sensitive clients
should consider multiple gateways, caching, batching, and privacy-preserving
transports.

# Operational Considerations

KID documents should be small, stable, and easy to cache.  Large or frequently
changing service metadata should live in Capability Manifests or
application-specific documents rather than in the KID document itself.

Operators should publish manifests at multiple locations when possible.  A KID
document can include both content hashes and transport locations, allowing
clients to verify content regardless of retrieval path.

--- back

# Acknowledgements

The identity model in this document is informed by decentralized identifier
systems, signed service manifests, self-authenticating records, and the need to
avoid conflating transferable names with persistent cryptographic identities.
