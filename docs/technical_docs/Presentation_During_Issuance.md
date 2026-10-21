# Verifiable Credential Issuance with Presentation During Issuance

This document outlines the process for Verifiable Credential (VC) issuance, particularly focusing on scenarios requiring a "Presentation During Issuance" by the user.

## Problem Statement: The Need for Presentation During Issuance

In many credential issuance scenarios, an issuer needs to verify certain attributes or existing credentials of a user *before* issuing a new credential.

For example, to issue a "Proof of Employment" credential, an employer (issuer) might first require the individual (user) to present their "Identity Card" credential and perhaps a "Signed Contract" document. This pre-issuance verification, often facilitated by a Verifiable Presentation, ensures the user meets the necessary prerequisites and provides cryptographically verifiable proof of their eligibility. Without this step, issuers might lack sufficient assurance or rely on less secure, non-standardized methods to validate prerequisite conditions, potentially leading to the issuance of credentials based on unverified or weakly verified claims. Presentation during issuance addresses this by integrating a formal verification step into the issuance flow.

## Solution Overview

The solution involves a multiphase interaction between the User's Wallet and the Credential Issuer (Inji Certify), which performs VP verification in-process via the embedded `verify-core` library.
The Wallet first discovers the Issuer's and auth server's capabilities.
Wallet then initiates the authorization by dictating it supports `urn:openid:dcp:iae:openid4vp_presentation`, and `urn:openid:dcp:iae:redirect_to_web` flow.
Certify invokes the embedded `verify-core` library to create a presentation request, which is then sent back to the Wallet. The Wallet retrieves the presentation request and prompts the User for consent to share existing credentials.
Once VP is verified, Wallet receives the authorization code and exchanges an authorization code for tokens, and finally requests and receives the new Verifiable Credential. This ensures that credentials are only issued after appropriate prerequisite verifications have been successfully completed.

## The Actors

The issuance process involves communication between four key participants:

* **User**: The individual who requests a new credential and provides consent to share existing credentials from their Wallet.

* **Wallet**: The user's agent (e.g., a mobile app) that stores their credentials, manages interactions with other systems, and requests new credentials on the user's behalf.

* **Inji Certify (VCI)**: The Credential Issuer. This system is responsible for issuing new verifiable credentials after validating the user's eligibility. It also acts as an OAuth Authorization Server.

* **VP Verifier**: A service that formally requests and verifies a Verifiable Presentation (VP) from the user's wallet to confirm they meet certain criteria. This is often based on OpenID4VP.

> **Implementation note:** In Inji Certify the **VP Verifier** is not a separately deployed service — it is the **Inji Verify (`verify-core`) library embedded in-process** in Certify. The presentation request is expressed using **DCQL**. See [Inji Verify as a Library](./Inji_Verify_As_A_Library.md) and [DCQL Support](./DCQL_Support.md) for details.

## Sequence Diagram

```mermaid
sequenceDiagram
    participant U as 👤 User
    participant W as 👜 Wallet
    participant IC as 🛡️ Inji Certify<br/>(OAuth AS + VCI)
    participant IVP as ⚙️ verify-core<br/>(embedded in Certify)

    U->>W: Opens the wallet
    Note over W,IC: 0. Discovery
    W->>IC: 1. GET /.well-known/openid-credential-issuer
    IC-->>W: 2. Credential Issuer metadata
    W->>IC: 3. GET /.well-known/oauth-authorization-server
    IC-->>W: 4. OAuth Authorization server(AS) metadata 
    
    Note over W,IC: 1. Authorization to download credential
    W->>IC: 5. POST Content-Type: application/x-www-form-urlencoded /oauth/iae<br/>{response_type="code", client_id, code_challenge, code_challenge_method:"S256", redirect_uri, interaction_types_supported=urn:openid:dcp:iae:openid4vp_presentation,urn:openid:dcp:iae:redirect_to_web}
    IC->>IVP: 6. Create presentation request
    IVP-->>IC: 7. {request_id,transaction_id, {standard ovp request by value with response_mode as "direct_post" or "direct_post.jwt"}} (non-normative)
    IC->>IC: 8. store transaction id for the presentation request mapped to Auth Session
    Note over IC: Map direct_post to iae_post and direct_post.jwt to iae_post.jwt and construct the response
    IC-->>W: 9. 200 Interactive Authorization Response<br/>{status:"require_interaction", type:"urn:openid:dcp:iae:openid4vp_presentation", auth_session:"..random string", openid4vp_request: {standard ovp request by value with response_mode "iae_post" — only iae_post (unencrypted) is supported for now}}
    
    Note over W,IC: 2. Presentation Flow (verification via embedded verify-core)
    W->>W: 10. Display and select credential(s) which satisfies presentation request criteria
    W->>U: 11. User consent
    U-->>W: 12. Approve
    W->>IC: 13. POST Content-Type: application/x-www-form-urlencoded /oauth/iae<br/>{auth_session=...&openid4vp_response=...}
    IC->>IC: 14. Validate auth_session
    IC->>IVP: 15. Submit vp_token with the stored request context to embedded verify-core (in-process — no external /oid4vp/response call)
    IVP->>IVP: 16. verify the VP response against the DCQL query
    IVP->>IC: 17. VP verification result (e.g., valid/invalid)
    
    alt If VP is valid 
            IC-->>W: 18. 200 OK {status:"ok", code:"..."}
            W->>IC: 19. POST /oauth/token<br/>{grant_type=authorization_code, code}
            IC-->>W: 20. {access_token, token_type, expires_in}
            W->>IC: 20a. POST /nonce (obtain c_nonce for the proof)
            IC-->>W: 20b. {c_nonce}
            W->>IC: 21. POST /issuance/credential<br/>{credential_configuration_id, proof with c_nonce}
            IC-->>W: 22. {credential}
    else
            IC-->>W: 18. 400 Bad Request {status:"error"}
    end
    
```

## Verifiable Credential Issuance Flow (Detailed Steps)

The process is broken down into several key phases:

### Phase 0: Discovery

The Wallet discovers the Credential Issuer's(Inji Certify) and Authorization Server's(Inji Certify) capabilities

1. **Wallet to Inji Certify**: `GET /.well-known/openid-credential-issuer` (The Wallet requests Inji Certify's OpenID Credential Issuer metadata).
2. **Inji Certify to Wallet**: Returns Credential Issuer metadata.
3. **Wallet to Inji Certify**: `GET /.well-known/oauth-authorization-server` (The Wallet requests Inji Certify's OAuth Authorization Server metadata).
4. **Inji Certify to Wallet**: Returns OAuth AS metadata.

### Phase 1: Authorization to download credential

The Wallet initiates the request, and the Issuer determines if a presentation is needed.
1. **Wallet to Inji Certify**: `POST /oauth/iae` (Includes `response_type="code"`, `client_id`, `code_challenge`, `code_challenge_method:"S256"`, `redirect_uri`, `interaction_types_supported=urn:openid:dcp:iae:openid4vp_presentation,urn:openid:dcp:iae:redirect_to_web` for the desired credential).
2. **Inji Certify**: Evaluates incoming request and identifies whether a Verifiable Presentation (VP) is required for the credential issuance.
    - If a VP is required, it proceeds to create a presentation request using the embedded `verify-core` library.
    - If no VP is required, it continues with authorization code flow. (That is as per standard OpenId4VCI spec, not included here)
3. **Inji Certify (embedded verify-core)**: Calls the embedded `verify-core` library in-process to create a presentation request.
4. **verify-core to Inji Certify**: Returns `request_id`, `transaction_id`, and `request` (e.g. `{response_type": "vp_token","response_mode": "direct_post"....}`). Inji Certify stores `transaction_id` mapped to the Auth Session.
5. **Inji Certify to Wallet**: Responds with `200 Interactive Authorization Response`. Includes `status:"require_interaction"`, `type:"urn:openid:dcp:iae:openid4vp_presentation"`, `auth_session`, `openid4vp_request:{}`
    - The `openid4vp_request` contains the standard OpenID4VP request by value. Only `response_mode` `iae_post` (unencrypted response) is supported for now; `iae_post.jwt` (encrypted response) is not yet processed. [Refer](https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-1_1-wg-draft.html#name-interactive-authorization)

### Phase 2: Presentation Flow (verification via embedded verify-core)

The Wallet interacts only with Inji Certify; VP verification happens in-process via the embedded `verify-core` library.
1. **Wallet**: Display and select credential(s) which satisfies presentation request criteria
2. **Wallet to User**: Prompts User for consent.
3. **User to Wallet**: User approves.
4. **Wallet to Inji Certify**: Send VP response
    - POST Content-Type: application/x-www-form-urlencoded /oauth/iae<br/>{auth_session=...&openid4vp_response=...}
    - if response_mode is `iae_post` then openid4vp_response is unencrypted, `{"vp_token": {...}}` — the `vp_token` is keyed by DCQL query id; DCQL mode does not use `presentation_submission`
    - `iae_post.jwt` is not supported by the current `/oauth/iae` processing path. It supplies an encrypted `{response='...'}` value, but the handler does not decode it into `vp_token`.
5. **Inji Certify**: Validates `auth_session`
6. **Inji Certify (embedded verify-core)**: For `iae_post`, passes the `vp_token` and the stored request context to the embedded Inji Verify (`verify-core`) library.
7. **verify-core**: Verifies the VP response against the DCQL query.
8. **verify-core to Inji Certify**: Returns the VP verification result (e.g., valid/invalid).
9. **Inji Certify**: Confirms VC is Valid (positive flow).
10. **Inji Certify to Wallet**: Responds with `200 OK` and `status:"ok"` along with a `code`.
11. **Wallet to Inji Certify**: `POST /oauth/token` (includes `grant_type="authorization_code"`, `code`).
12. **Inji Certify to Wallet**: Responds with `access_token`, `token_type`, `expires_in` (no `c_nonce` — the token response does not carry a nonce).
13. **Wallet to Inji Certify**: `POST /nonce` to obtain a `c_nonce`, then `POST /issuance/credential` (includes `credential_configuration_id`, `proof` with the `c_nonce`, authenticated with `access_token`).
14. **Inji Certify to Wallet**: Validates and returns the `credential`.

## Specifications Used

This flow is based on concepts and standards from the following documents:

* [RFC 8414 - OAuth 2.0 Authorization Server Metadata](https://tools.ietf.org/html/rfc8414)

* [OpenID for Verifiable Credential Issuance (OID4VCI) - Editor Draft](https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-1_1-wg-draft.html#name-interactive-authorization)

* [GitHub issue from OpenID4VCI](https://github.com/openid/OpenID4VCI/issues/473)
