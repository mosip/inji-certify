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

When adding or updating a configuration, you need to send a JSON object with details related to the credential format you are configuring. The required fields depend on the credential format (e.g., `ldp_vc`, `mso_mdoc`, `vc+sd-jwt`). For more details regarding the API fields and examples, refer to the [Inji Certify API docs](https://mosip.stoplight.io/docs/inji-certify).

---

## Configuration Properties

The Inji Certify uses several configuration properties to control how credential configurations work. These are typically set in your `application.properties` or `application.yml` file.

| Property Name                                                          | Description                                                                              | Example Value                                                                                                                                                                                                                                                                                     |
|------------------------------------------------------------------------|------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `mosip.certify.data-provider-plugin.credential-status.supported-purposes` | List of supported credential status purposes. Default value 'revocation'.                | `["suspension", "revocation"]`                                                                                                                                                                                                                                                                    |
| `mosip.certify.credential-config.cryptographic-binding-methods-supported` | Supported cryptographic binding methods per credential format.                           | `{ 'ldp_vc': {'did:jwk','did:key'}, 'mso_mdoc': {'cose_key'},'vc+sd-jwt': {'did:jwk','did:key'} }`                                                                                                                                                                                                |
| `mosip.certify.credential-config.credential-signing-alg-values-supported` | Supported signing algorithms per crypto suite.                                           | `{ 'RsaSignature2018': {'RS256'}, 'Ed25519Signature2018': {'EdDSA'}, 'Ed25519Signature2020': {'EdDSA'}, 'EcdsaKoblitzSignature2016': {'ES256K'}, 'EcdsaSecp256k1Signature2019': {'ES256K'}, 'EcdsaSecp256r1Signature2019': {'ES256'}, 'ecdsa-rdfc-2019': {'ES256'}, 'ecdsa-jcs-2019': {'ES256'}}` |
| `mosip.certify.credential-config.proof-types-supported`                | Supported proof types for credentials.                                                   | `{'jwt': {'proof_signing_alg_values_supported': {'RS256', 'PS256', 'ES256', 'EdDSA'}}}`                                                                                                                                                                                                           |

## Validations and Rules

**Note** : 
In case of VCIssuance plugin mode, `ldp_vc` and `mso_mdoc` formats are supported by credential-configurations endpoints. 
In case of DataProviderPlugin mode, `ldp_vc` and `vc+sd-jwt` formats are supported by credential-configurations endpoints.

Inji Certify checks your configuration for required fields and possible duplicates:

- **Required fields** depend on the credential format.
- **No duplicate configurations**: You cannot add two configurations with the same key details. For example, 
  - for `ldp_vc` format, combination of context & type should be unique. 
  - for `mso_mdoc` format, docType value should be unique.
  - for `vc+sd-jwt` format, sdJwtVct value should be unique.

If you miss a required field or try to add a duplicate, Certify will return an error.

---