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
| `mosip.certify.credential-config.credential-signing-alg-values-supported` | Supported signing algorithms per crypto suite.                            | `{ 'RsaSignature2018': {'RS256'}, 'Ed25519Signature2018': {'EdDSA'}, 'Ed25519Signature2020': {'EdDSA'}, 'EcdsaKoblitzSignature2016': {'ES256K'}, 'EcdsaSecp256k1Signature2019': {'ES256K'}, 'EcdsaSecp256r1Signature2019': {'ES256'}, 'ecdsa-rdfc-2019': {'ES256'}, 'ecdsa-jcs-2019': {'ES256'}}` |
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
  - `signatureCryptoSuite` must be one of the supported suites defined in `mosip.certify.credential-config.credential-signing-alg-values-supported`.
  - `signatureAlgo` must be one of the supported algorithms for the chosen `signatureCryptoSuite`.
  - `keyManagerAppId` and `keyManagerRefId` must refer to the correct keys defined in `mosip.certify.signature-algo.key-alias-mapper`.
- **Per-configuration selection of `cryptographicBindingMethodsSupported`, `credentialSigningAlgValuesSupported` and `proofTypesSupported`**.
  - All three are optional in the Add and Update Credential Configuration requests, and are always returned by the Get response, except for a configuration without holder binding (see below).
  - The configuration properties above are the authoritative allow-list. A request can select from or narrow what the deployment declares; it can never exceed it.
  - `cryptographicBindingMethodsSupported` is validated against the methods declared for the credential format in `mosip.certify.credential-config.cryptographic-binding-methods-supported`.
  - `credentialSigningAlgValuesSupported` is validated against the algorithms declared for the chosen `signatureCryptoSuite` in `mosip.certify.credential-config.credential-signing-alg-values-supported`. For a format that carries no crypto suite, such as `dc+sd-jwt`, it is validated against `mosip.certify.signature-algo.key-alias-mapper`, so only an algorithm the deployment actually holds a signing key for is accepted. This key check applies only to the algorithms a request provides. Where the attribute is omitted, the value derived from the configuration's own `signatureAlgo` is stored as it stands, so a deployment that declares an algorithm it holds no key for surfaces that at issuance rather than at configuration time.
  - For the `mso_mdoc` format the algorithms are advertised as COSE identifiers, so every value must be `ES256`, the only algorithm supported for an mdoc's issuerAuth. `EdDSA`, `RS256` and `ES256K` are rejected. This applies to what a request selects and equally to what is derived from the crypto suite when the request selects nothing: either way any other value is rejected with `unsupported_credential_signing_alg`. A configuration stored before this check that still resolves to such a value is left out of the issuer metadata and logged, at startup and on each metadata request; correct it with the Update API.
  - `proofTypesSupported` is validated against `mosip.certify.credential-config.proof-types-supported`. Each proof type must be declared there, and its `proof_signing_alg_values_supported` must be a subset of the algorithms declared for that proof type. `proof_signing_alg_values_supported` is the only recognised attribute within a proof type entry.
  - A proof type named without a `proof_signing_alg_values_supported` list is stored with the full set declared for it, rather than with no algorithms at all. Storing it bare would publish a proof type carrying no algorithms, which OpenID4VCI does not allow, and proof validation reads a missing list as an empty one and rejects every proof. If the deployment declares no algorithms for that proof type either, the request fails rather than storing one with an empty list — correct `mosip.certify.credential-config.proof-types-supported` first.
  - **When an attribute is omitted on Add**, the value derived from configuration applies: the full set of binding methods declared for the credential format, the algorithms declared for the crypto suite (or the configuration's own `signatureAlgo` where there is no suite), and all declared proof types.
  - **When an attribute is omitted on Update**, the previously stored value is retained rather than re-derived from the current configuration, so an issuer's earlier explicit selection is never silently discarded. The one exception is a legacy row whose `credentialSigningAlgValuesSupported` holds a crypto suite name: that is normalised to the algorithms the suite stands for, so what the configuration advertises is unchanged.
  - An attribute that is present but empty is rejected, except `cryptographicBindingMethodsSupported` and `proofTypesSupported` sent empty together (see below). If several values across the three attributes are invalid, all of them are reported together so the payload can be corrected in a single pass.
  - Whatever is stored against a credential configuration is what the credential issuer metadata advertises for it.
  - **Without holder binding**: sending `cryptographicBindingMethodsSupported` as `[]` and `proofTypesSupported` as `{}` configures the credential without holder binding. Both are stored as NULL, no proof is required at issuance, and neither the Get response nor the issuer metadata includes them. An update that omits both keeps the configuration unbound; sending both non-empty binds it again.
    - `mso_mdoc` is always holder-bound, as ISO/IEC 18013-5 requires `deviceKeyInfo` in the mobile security object, so it cannot be configured this way.
    - For an unbound `ldp_vc`, guard the holder id in the VC template, for example `#if($_holderId)"id": "${_holderId}",#end`. Without the guard the literal `${_holderId}` ends up in the credential.
- **Purpose of `didUrl` in `credential_config`**:
  - `didUrl` in `credential_config` can be different from the issuer did url specified by the property `mosip.certify.data-provider-plugin.did-url`.
  - It is used to point to temporary `didUrl` which is specific to a VC type. The did document fetched from the `./well-known/did.json` endpoint can be copied and hosted on the credentialConfig didUrl.
  - **Example**: `mosip.certify.data-provider-plugin.did-url=did:mosip:12345`
  - `credential_config.didUrl=did:mosip:12345:driver_license`
  - In this case, the did document for `did:mosip:12345:driver_license` can be copied from `did:mosip:12345` and hosted on this url.
    
If you miss a required field or try to add a duplicate, Certify will return an error.

---