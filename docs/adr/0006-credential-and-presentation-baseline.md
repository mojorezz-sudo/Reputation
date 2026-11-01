# ADR 0006: Credential and presentation baseline

- Status: Accepted for prototype
- Date: 2026-11-01

## Context

The next Sprint 1 boundary is credential issuance and verifier presentation for the first reputation primitive, `OnchainAge`.

This decision must avoid two forms of lock-in:

1. coupling reputation semantics to one credential encoding; and
2. adopting a credential-profile draft merely because it currently has convenient wallet tooling.

There is also a standards-version seam in late 2026:

- W3C Verifiable Credentials Data Model 2.0 is a Recommendation.
- W3C `Securing Verifiable Credentials using JOSE and COSE` became a Recommendation in October 2026 and defines `application/vc+jwt`, `application/vp+jwt`, `application/vc+sd-jwt`, and related processing for VC Data Model 2.0.
- OpenID4VCI 1.0 and OpenID4VP 1.0 are Final Specifications from 2025 and are credential-format agnostic at the protocol level, but their built-in W3C JWT profile `jwt_vc_json` demonstrates the older nested `vc` claim convention.
- The current IETF SD-JWT VC specification remains an Internet-Draft in October 2026.
- W3C BBS selective-disclosure cryptosuites remain Candidate Recommendation work in 2026.

We should therefore separate modern credential semantics/security from transport/profile adapters.

## Decision

### 1. Core credential semantics

Use W3C Verifiable Credentials Data Model 2.0 as the semantic model.

The initial `OnchainAge` credential is a narrowly scoped positive credential. It states that a defined threshold was satisfied under a versioned methodology and declared source coverage.

It does **not** state that the holder is trustworthy, creditworthy, experienced, profitable, or continuously controlled the source wallet throughout history.

### 2. Initial secured encoding

Use the W3C JOSE/COSE Recommendation's JWT envelope for the first prototype:

- media type: `application/vc+jwt`
- protected JOSE `typ`: `vc+jwt`
- signing algorithm: ES256 for the prototype
- issuer key selected by a `kid`
- VC Data Model 2.0 properties are encoded directly in the JWT Claims Set
- the legacy nested JWT claim named `vc` is not used

The implementation must use a mature JOSE library rather than constructing JWS signatures or JOSE verification manually.

Initial library candidate: `jose`, pinned to an exact reviewed version.

### 3. Credential codec abstraction

Credential semantics must not depend on JWT.

Introduce a project-owned credential codec boundary so that later encodings can be added without changing `OnchainAge`, `LendingHistory`, or other reputation methodology.

Conceptually:

`reputation result -> credential model -> credential codec -> secured credential`

Future codecs may include:

- `application/vc+sd-jwt`
- a mature SD-JWT VC profile
- Data Integrity selective-disclosure suites
- BBS-based derived proofs

No future codec is assumed to be equivalent in privacy properties; each requires its own threat/privacy review.

### 4. Issuer key boundary

Issuer signing keys must be outside credential-domain logic.

Prototype tests may use ephemeral generated keys.

Production keys will require managed KMS/HSM storage, rotation, separation of duties, published verification metadata, and emergency key-revocation procedures.

No production issuer private key is stored in the repository or application configuration files.

### 5. Holder binding without a public wallet identifier

The credential must not contain the source EVM wallet address by default.

The credential also must not require a persistent global holder identifier.

For the prototype, the holder creates a dedicated P-256 key pair for the credential. The issuer binds the credential to the holder's public proof-of-possession key using the JOSE/JWT `cnf` mechanism described by the W3C JOSE/COSE Recommendation.

The credential may carry the holder public JWK in `cnf.jwk` for the sandbox implementation.

Important privacy rule:

- use a fresh holder key per credential by default;
- do not reuse one global reputation key across unrelated credentials or verifiers;
- never derive this key directly from an EVM wallet private key.

This prevents the credential from publicly exposing the wallet and reduces cross-credential correlation.

### 6. Issuance is bound to fresh wallet control

The credential issuer must orchestrate its own `OnchainAge` evaluation from a successful wallet-ownership verification result.

A caller must not be able to submit an arbitrary precomputed `OnchainAgeResult` and ask the issuer to sign it.

The issuer therefore receives a successful ownership proof, checks that the ownership verification is sufficiently fresh, then invokes `OnchainAgeService` using that verified address and chain.

Only a `satisfied` result creates an `OnchainAge` credential.

We do not issue portable negative reputation credentials in the first MVP.

### 7. Credential contents

Verifier-facing `OnchainAge` credentials should contain the minimum useful facts, including:

- VC 2.0 context and types
- credential schema/version identifier
- issuer
- validity window
- reputation primitive: `OnchainAge`
- chain ID
- proven threshold date
- methodology version
- minimal source-coverage metadata needed to interpret the claim

They should not contain by default:

- source wallet address
- full wallet list
- exact balance
- full transaction history
- evidence transaction hash
- persistent global holder identifier

An internal issuance audit trace may retain evidence references according to the privacy/retention policy; that trace is not automatically disclosed to verifiers.

### 8. Credential lifetime

`OnchainAge` changes slowly, but current-control continuity can change immediately if a wallet is transferred or compromised.

For the sandbox prototype:

- default credential validity: 7 days
- maximum configurable validity: 30 days

This is intentionally shorter than the historical fact itself. The duration will be revisited after recovery/revocation and holder-continuity design are stronger.

### 9. Presentation format

Use the same modern W3C JOSE/COSE Recommendation for presentations:

- VC is represented as an `EnvelopedVerifiableCredential` carrying the `application/vc+jwt` secured credential;
- the presentation follows VC Data Model 2.0;
- presentation media type: `application/vp+jwt`;
- protected JOSE `typ`: `vp+jwt`;
- the holder signs the short-lived presentation with the credential-bound holder key.

The holder presentation is verifier-bound.

### 10. Verifier challenge and replay protection

Before presentation, the verifier creates a short-lived request containing at least:

- requested credential type/policy
- audience/verifier identifier
- fresh cryptographic nonce
- issued-at and expiry
- threshold requirement
- acceptable methodology version(s)

The presentation JWT must bind to:

- the verifier audience via `aud`
- the exact verifier nonce
- short `iat` / `exp`
- the credential being presented

Verifier requests are single-use. Consumption semantics follow the wallet-ownership challenge principle: a successfully matched request is consumed before final cryptographic acceptance, so concurrent replay cannot produce multiple accepted presentations.

### 11. Verifier result semantics

Verifier API results remain three-valued:

- `satisfied`
- `not_satisfied`
- `unverifiable`

However, the first portable credential flow issues **positive credentials only**.

Therefore:

- valid credential satisfying policy -> `satisfied`
- missing/expired/insufficient positive credential -> generally `unverifiable`, not `not_satisfied`

`not_satisfied` must only be returned when there is affirmative evidence supporting the negative conclusion. Absence of a positive credential is not proof of failure.

### 12. OpenID4VCI / OpenID4VP

Do not bake OpenID transport fields into the credential domain model.

OpenID4VCI and OpenID4VP remain the preferred interoperability transport direction because both are Final Specifications and support multiple credential formats.

For the first sandbox, implement the credential/presentation cryptographic and replay boundaries independently behind project interfaces.

Add an OpenID4VCI/VP adapter only after we choose an explicit format profile compatible with our modern VC 2.0 encoding. We will not silently fall back to the older `jwt_vc_json` nested-`vc` convention just to match a built-in appendix profile.

### 13. Selective disclosure / ZK

Plain `vc+jwt` is **not** selective disclosure. A verifier receiving the credential can read all claims in that credential.

We mitigate this initially by making each credential narrow and minimal: one reputation primitive per credential, no raw wallet identity, and no unnecessary evidence.

Selective disclosure is a subsequent codec/privacy milestone, not something we pretend the first JWS credential provides.

Current candidates to evaluate later:

- W3C `application/vc+sd-jwt`
- IETF SD-JWT VC once its standards status/profile is sufficiently stable for our interoperability needs
- W3C Data Integrity BBS once the relevant cryptosuite reaches suitable maturity and implementation quality

## Security properties

- Reputation methodology is independent from credential serialization.
- No custom cryptographic signing format.
- No source wallet address required in the credential.
- Holder proof uses a credential-specific key rather than the wallet key.
- Issuance is derived from a fresh wallet-control proof, not caller-supplied reputation output.
- Presentations are audience-, nonce-, and expiry-bound.
- Replay cannot be interpreted as a new verifier approval.
- Missing credentials do not create false negative reputation.

## Trade-offs

- Plain JWT credentials are linkable if the exact same credential is shown to multiple verifiers.
- Per-credential holder keys reduce cross-credential correlation but do not make repeated presentation of the same credential unlinkable.
- Full OpenID4VC interoperability is deferred until the format-profile seam is explicitly resolved.
- Carrying `cnf.jwk` increases credential size but gives a simple sandbox proof-of-possession binding without a public holder DID.
- Revocation/status remains a separate implementation decision; short expiry reduces but does not remove that need.

## Revisit if

- OpenID publishes/updates a profile directly aligned with modern VC 2.0 `application/vc+jwt` / `application/vc+sd-jwt` processing;
- IETF SD-JWT VC becomes an RFC with mature interoperable implementations;
- BBS/selective-disclosure implementation maturity justifies earlier adoption;
- pairwise verifier binding requires a different holder-key model;
- credential replay/linkability tests show that narrow JWT credentials are insufficient even for the sandbox;
- status/revocation design requires changing holder binding or key discovery.
