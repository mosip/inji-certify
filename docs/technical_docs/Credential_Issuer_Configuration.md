# Credential Configuration

This guide explains how to manage (add, update, view, and delete) credential configurations in the Inji Certify service. These configurations tell Inji Certify how to issue different types of Verifiable Credentials using various formats and settings.

## What is a Credential Configuration?

A credential configuration defines the rules and details for issuing a specific type of digital credential. For example, it specifies the format, signing method, and any templates or types needed for the credential.

## Why is this important?

Before Inji Certify can issue a new type of credential, you need to define its configuration using the API endpoints described below. Additionally, this configuration will be used in openid-credential-issuer metadata to help clients understand how to interact with the credential issuer. This is crucial for ensuring that the credentials are issued correctly and can be verified by other systems.

---

## Available API Endpoints

You can use these endpoints to manage your credential configurations:

1. **Add a New Configuration**
    - **POST** `/credential-configurations`
    - Use this to create a new credential configuration.
    - You must provide all required details in the request body.

2. **Get a Configuration by ID**
    - **GET** `/credential-configurations/{credentialConfigKeyId}`
    - Use this to view the details of a specific configuration.

3. **Update an Existing Configuration**
    - **PUT** `/credential-configurations/{credentialConfigKeyId}`
    - Use this to change the details of an existing configuration.

4. **Delete a Configuration**
    - **DELETE** `/credential-configurations/{credentialConfigKeyId}`
    - Use this to remove a configuration you no longer need.

---

## What Information Do You Need to Provide?

When adding or updating a configuration, you need to send a JSON object with details related to the credential format you are configuring. The required fields depend on the credential format (e.g., `ldp_vc`, `mso_mdoc`, `dc+sd-jwt`). For more details regarding the API fields and examples, refer to the [Inji Certify API docs](https://mosip.stoplight.io/docs/inji-certify).

---

## Configuration Properties

The Inji Certify uses several configuration properties to control how credential configurations work. These are typically set in your `application.properties` or `application.yml` file.

| Property Name                                                          | Description                                                               | Example Value                                                                                                                                                                                                                                                                                     |
|------------------------------------------------------------------------|---------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `mosip.certify.data-provider-plugin.credential-status.allowed-status-purposes` | List of supported credential status purposes. Default value 'revocation'. | `["suspension", "revocation"]`                                                                                                                                                                                                                                                                    |
| `mosip.certify.credential-config.cryptographic-binding-methods-supported` | Supported cryptographic binding methods per credential format.            | `{ 'ldp_vc': {'did:jwk','did:key'}, 'mso_mdoc': {'cose_key'},'dc+sd-jwt': {'did:jwk','did:key'} }`                                                                                                                                                                                                |
| `mosip.certify.credential-config.credential-signing-alg-values-supported` | Signing algorithms each credential configuration may use, grouped by credential format: for `ldp_vc` per crypto suite, for `mso_mdoc` and `dc+sd-jwt` as a list. The original shape, keyed by crypto suite only, is still read. | `{ 'ldp_vc': {'Ed25519Signature2020': {'EdDSA'}, 'EcdsaSecp256r1Signature2019': {'ES256'}, 'eddsa-rdfc-2022': {'EdDSA'}, 'ecdsa-rdfc-2019': {'ES256'}}, 'mso_mdoc': {'ES256'}, 'dc+sd-jwt': {'RS256', 'EdDSA', 'ES256K', 'ES256'} }` |
| `mosip.certify.credential-config.proof-types-supported`                | Supported proof types for credentials.                                    | `{'jwt': {'proof_signing_alg_values_supported': {'RS256', 'PS256', 'ES256', 'EdDSA'}}}`                                                                                                                                                                                                           |
| `mosip.certify.signature-algo.key-alias-mapper`                       | Maps signature algorithms to list of key-aliases in key_alias table.      | `{'EdDSA': {{'CERTIFY_VC_SIGN_ED25519', ''}, {'CERTIFY_VC_SIGN_ED25519', 'ED25519_SIGN'}}`                                                                                                                                                                                                        |

## Validations and Rules

**Note** : 
In case of VCIssuance plugin mode, `ldp_vc` and `mso_mdoc` formats are supported by credential-configurations endpoints. 
In case of DataProviderPlugin mode, `ldp_vc` and `dc+sd-jwt` formats are supported by credential-configurations endpoints.

Inji Certify checks your configuration for required fields and possible duplicates:

- **Required fields** depend on the credential format.
- **No duplicate configurations**: You cannot add two configurations with the same key details. For example, 
  - for `ldp_vc` format, combination of context & type should be unique. 
  - for `mso_mdoc` format, docType value should be unique.
  - for `dc+sd-jwt` format, sdJwtVct value should be unique.
- **Validation for `signatureCryptoSuite`, `signatureAlgo`, `keyManagerAppId`, `keyManagerRefId`**.
  - `signatureAlgo` is mandatory for every credential format, on Add and on Update. It is the algorithm the credential is signed with, and nothing is filled in for it from the properties: a request that leaves it out is rejected (`invalid_request`, or `mso_mdoc_mandatory_fields_missing` / `dc_sd_jwt_mandatory_fields_missing` for those formats).
  - `ldp_vc`: `signatureCryptoSuite` is mandatory and must be declared in `mosip.certify.credential-config.credential-signing-alg-values-supported` (under `'ldp_vc'` when the property is grouped by format), and `signatureAlgo` must be one of the algorithms declared for that suite.
  - `mso_mdoc`: an mdoc's issuerAuth is signed with `signatureAlgo` alone, so `signatureCryptoSuite` is not accepted; a request that sends one is rejected with `invalid_request`. `signatureAlgo` must be declared under `'mso_mdoc'` when the property is grouped by format, the deployment must hold a signing key for it, and it must be `ES256`, the only algorithm supported for an mdoc's issuerAuth. `EdDSA`, `RS256` and `ES256K` are rejected with `unsupported_credential_signing_alg`.
  - `dc+sd-jwt`: `signatureAlgo` must be declared under `'dc+sd-jwt'` when the property is grouped by format, and the deployment must hold a signing key for it in `mosip.certify.signature-algo.key-alias-mapper`.
  - Where the property is keyed by crypto suite only, `mso_mdoc` and `dc+sd-jwt` accept any algorithm the deployment holds a signing key for.
  - `keyManagerAppId` and `keyManagerRefId` must refer to the correct keys defined in `mosip.certify.signature-algo.key-alias-mapper`.
- **What the credential issuer metadata advertises in `credential_signing_alg_values_supported`**.
  - It is derived from the credential configuration; the Add and Update requests no longer take a `credentialSigningAlgValuesSupported` list, and a value sent for it is ignored. Each configuration advertises the one value it is signed with, so what is advertised can never differ from how the credential is signed.
  - `ldp_vc` advertises its `signatureCryptoSuite`, for example `Ed25519Signature2020` or `eddsa-rdfc-2022`, as OpenID4VCI 1.0 Appendix A.1.2.2 requires. A JWS algorithm such as `EdDSA` stands for more than one suite, so a wallet could not act on it.
  - `dc+sd-jwt` advertises its `signatureAlgo`, for example `ES256`, and `mso_mdoc` advertises the COSE identifier of its `signatureAlgo`, `-7` for `ES256`.
  - Existing `ldp_vc` configurations advertise their crypto suite without being re-submitted.
- **Per-configuration selection of `cryptographicBindingMethodsSupported` and `proofTypesSupported`**.
  - Both are mandatory in the Add and Update Credential Configuration requests, and are always returned by the Get response. A request that leaves one out, sends it as `null` or sends it empty is rejected with `invalid_request`, naming the attribute.
  - The configuration properties above are the allow-list, and only the allow-list. A request can select from or narrow what the deployment declares; it can never exceed it, and nothing is filled in from the properties when a value is missing.
  - `cryptographicBindingMethodsSupported` is validated against the methods declared for the credential format in `mosip.certify.credential-config.cryptographic-binding-methods-supported`.
  - `proofTypesSupported` is validated against `mosip.certify.credential-config.proof-types-supported`. Each proof type must be declared there and must carry a non-empty `proof_signing_alg_values_supported`, which must be a subset of the algorithms declared for that proof type. `proof_signing_alg_values_supported` is the only recognised attribute within a proof type entry. A proof type sent as `null`, without `proof_signing_alg_values_supported`, or with an empty list is rejected with `invalid_request`.
  - A deployment may declare a proof type with no proof signing algorithms. It still starts and serves requests; only a request naming that proof type is rejected.
  - On Update both are sent again and replace what is stored. Any valid selection may be changed to any other valid selection.
  - If several values across the attributes and the signing algorithm are invalid, all of them are reported together so the payload can be corrected in a single pass.
  - A value listed more than once, in either attribute or in a proof type's `proof_signing_alg_values_supported`, is stored once, in the order first given. The request is not rejected for it; for example, `["did:jwk", "did:jwk"]` is stored as `["did:jwk"]`.
  - Whatever is stored against a credential configuration is what the Get response returns and the credential issuer metadata advertises for it.
  - **Configurations created before these attributes were stored** need not be re-submitted. Where nothing is stored for an attribute, the Get response and the issuer metadata keep resolving it from the properties as before.
  - **Upgrading existing automation:** every Update request must now send both attributes and `signatureAlgo`, even one that only changes an unrelated field such as the display name. A script or client that omits any of them receives an error. `credentialSigningAlgValuesSupported` can be dropped from requests; an `mso_mdoc` request must also drop `signatureCryptoSuite`.
  - An empty `cryptographicBindingMethodsSupported` or `proofTypesSupported` is rejected for now.
- **Purpose of `didUrl` in `credential_config`**:
  - `didUrl` in `credential_config` can be different from the issuer did url specified by the property `mosip.certify.data-provider-plugin.did-url`.
  - It is used to point to temporary `didUrl` which is specific to a VC type. The did document fetched from the `./well-known/did.json` endpoint can be copied and hosted on the credentialConfig didUrl.
  - **Example**: `mosip.certify.data-provider-plugin.did-url=did:mosip:12345`
  - `credential_config.didUrl=did:mosip:12345:driver_license`
  - In this case, the did document for `did:mosip:12345:driver_license` can be copied from `did:mosip:12345` and hosted on this url.
    
If you miss a required field or try to add a duplicate, Certify will return an error.

---