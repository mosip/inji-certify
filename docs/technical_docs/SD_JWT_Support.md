# SD-JWT Credential Support

This document explains how to configure and use SD-JWT (Selective Disclosure JWT) credential format in the Inji Certify service.

---

## 1. How to Configure SD-JWT Credentials

To add a new SD-JWT credential configuration, use the `/credential-configurations` endpoint with the following important fields in your JSON payload:

- **credentialFormat**: Must be set to `dc+sd-jwt`
- **signatureAlgo**: The signing algorithm (e.g., `ES256K`). It is validated against `mosip.certify.signature-algo.key-alias-mapper`: the deployment must hold a signing key for it, or the request is rejected with `key_chooser_config_not_found`. It is also the value the credential issuer metadata advertises in `credential_signing_alg_values_supported`.
- **sdJwtVct**: The VCT (Verifiable Credential Type) value for the credential
- **cryptographicBindingMethodsSupported**: The binding methods to advertise, chosen from those declared for `dc+sd-jwt` in `mosip.certify.credential-config.cryptographic-binding-methods-supported` (e.g., `["did:jwk"]`)
- **proofTypesSupported**: The proof types to accept, each with its proof signing algorithms, chosen from `mosip.certify.credential-config.proof-types-supported` (e.g., `{"jwt": {"proof_signing_alg_values_supported": ["ES256"]}}`)

`signatureAlgo`, `cryptographicBindingMethodsSupported` and `proofTypesSupported` are mandatory, and nothing is filled in from the properties when one is missing or empty. The request no longer takes a `credentialSigningAlgValuesSupported` list; a request that still sends it is rejected with `invalid_request`.

For full details on the required fields and how to structure your request with examples, refer to the [Inji Certify API documentation](https://mosip.stoplight.io/docs/inji-certify).

---

## 2. Specific Configurations Required

Add the following properties to your `application.yml` or `application.properties` to enable and control SD-JWT support:

| Property Name                                                          | Description                                                                                                                                                               | Example Value                                      |
|------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------|
| `mosip.certify.signature-algo.key-alias-mapper`                       | Maps each signing algorithm to its key aliases. An SD-JWT configuration's `signatureAlgo` must be one of its keys.                                                        | `{'ES256': {{'CERTIFY_VC_SIGN_EC_R1', 'EC_SECP256R1_SIGN'}}}`              |
| `mosip.certify.credential-config.proof-types-supported`                | Supported proof types for SD-JWT                                                                                                                                          | `{'jwt': {'proof_signing_alg_values_supported': {'RS256', 'PS256', 'ES256', 'EdDSA'}}}`                     |
| `mosip.certify.credential-config.cryptographic-binding-methods-supported` | Supported binding methods for SD-JWT                                                                                                                                      | `{ 'ldp_vc': {'did:jwk','did:key'}, 'mso_mdoc': {'cose_key'},'dc+sd-jwt': {'did:jwk','did:key'} }`          |
| `mosip.certify.data-provider-plugin.did-url` | The base Decentralized Identifier document URL used by the data provider plugin to resolve and bind DIDs for credential issuance.                                         | `did:web:someuser.github.io:somerepo:somedirectory` |
|`mosip.kernel.keymanager.signature.kid.prepend`| The prefix to prepend to the `kid` field in SD-JWT credentials. This is useful for ensuring unique key identifiers across different systems. Default value will be blank. | `#`, `<DOMAIN_NAME>#` or `PAYLOAD_ISSUER`                          |
---

## 3. Sequence Diagram for SD-JWT Credential Issuance

```mermaid
sequenceDiagram
    participant Client as 🌐 Client
    box Inji Certify #E6F3FF
    participant CredentialAPI as 🔗 Credential API
    participant CredentialConfiguration as ⚙️ Credential Configuration
    participant DataProviderPlugin as 🔌 Data Provider Plugin
    participant VelocityTemplatingEngine as ⚙️ Velocity Templating Engine
    participant SDJWTCredential as 🔐 SDJWTCredential
    end

    Client->>CredentialAPI: Request VC Issuance (format: dc+sd-jwt)

    CredentialAPI->>CredentialConfiguration: Validate VC request & get template
    CredentialConfiguration-->>CredentialAPI: Return validation success & template

    CredentialAPI->>DataProviderPlugin: Request data
    DataProviderPlugin-->>CredentialAPI: Return raw data

    CredentialAPI->>VelocityTemplatingEngine: Format raw data with template
    VelocityTemplatingEngine-->>CredentialAPI: Return formatted credential data

    CredentialAPI->>SDJWTCredential: Instantiate with formatted data

    CredentialAPI->>SDJWTCredential: createCredential()
    note right of SDJWTCredential: Generates the SD-JWT structure with disclosures.
    SDJWTCredential-->>CredentialAPI: Return unsigned SD-JWT credential

    CredentialAPI->>SDJWTCredential: addProof(unsigned credential)
    note right of SDJWTCredential: Signs the JWT and adds the final proof alongwith disclosures.
    SDJWTCredential-->>CredentialAPI: Return signed dc+sd-jwt

    CredentialAPI-->>Client: Return final dc+sd-jwt
```

## 4. Configuring `kid` and DID Binding

### `kid` (Key ID)
- The `kid` field identifies the keyID of the certificate that is used for signing the VC.
- You can configure the `kid` prefix using the property `mosip.kernel.keymanager.signature.kid.prepend` to ensure uniqueness across different credentials.
  - if you set it to `#`, the `kid` will be prefixed with `#`. example: `#<KEY_ID>`
  - if you set it to `<DOMAIN_NAME>#`, the `kid` will be prefixed with the domain name followed by `#`. example: `example.com#<KEY_ID>`
  - if you set it to `PAYLOAD_ISSUER`, the `kid` will be prefixed with the issuer of the payload. example: `did:example:123#<KEY_ID>`

### DID Binding
- DID binding ensures the credential is cryptographically linked to a Decentralized Identifier (DID).
- The supported binding methods for SD-JWT are `did:jwk` and `did:key` (see configuration above).
- In the final SD-JWT credential, the `cnf` field in payload will contain the holderId in the following format : 
{... cnf": { "kid": "did:jwk:<HOLDER_ID>" ... }}

---

## Notes

- Ensure your signing keys, DIDs are properly registered and accessible to the Certify service.
- For more details on the API, see the [Inji Certify API docs](https://mosip.stoplight.io/docs/inji-certify).

---