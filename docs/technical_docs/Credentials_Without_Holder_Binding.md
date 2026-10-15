## Credentials Without Holder Binding
Inji Certify can issue a credential that is not bound to a key held by the wallet. The wallet sends no proof of possession, and the credential carries no holder key.

Use this only when the credential is meant to be presented by whoever holds a copy, such as a publicly shareable certificate. An unbound credential is a bearer credential: anyone who obtains it can present it, and a verifier cannot tell the holder from someone who copied it.

## Configuring a Credential Without Holder Binding
Send both `cryptographicBindingMethodsSupported` and `proofTypesSupported` empty in the Add or Update Credential Configuration request:

```json
{
  "credentialConfigKeyId": "FarmerCredentialNoBinding",
  "credentialFormat": "ldp_vc",
  "cryptographicBindingMethodsSupported": [],
  "proofTypesSupported": {}
}
```

 - Only one of the two sent empty is rejected. Both omitted gives a holder-bound configuration with the deployment's declared defaults.
 - `mso_mdoc` is always holder-bound, as ISO/IEC 18013-5 requires `deviceKeyInfo`, and cannot be configured this way.
 - The full rules, including updates, are in [Credential Configuration](./Credential_Issuer_Configuration.md#validations-and-rules).

## What Changes at Issuance
 - **Issuer metadata**: the configuration omits `cryptographic_binding_methods_supported` and `proof_types_supported`, as OpenID4VCI 1.0 allows. Wallets read this to decide whether to send a proof.
 - **Credential request**: `proofs` may be omitted. A proof sent anyway is ignored, so wallets that always send one keep working.
 - **Issued credential**:
   - `ldp_vc`: no `credentialSubject.id`. A template that renders `${_holderId}` unresolved or empty has the `id` removed before signing; guarding it with `#if($_holderId)"id": "${_holderId}",#end` keeps the intent explicit.
   - `dc+sd-jwt`: no `cnf` claim. Certify adds `cnf` itself, not the template, so the template needs no change. Do not reference `${_holderId}` in an SD-JWT template: outside `credentialSubject.id` an unresolved reference is not removed.
 - **Plugin mode**: only the DataProvider mode issues unbound credentials. In the VCIssuance mode a proof is always required, since the plugin issues holder-bound credentials. See [VCIssuance vs DataProvider](./VCIssuance_Vs_DataProvider.md).

## Database Migration
The `0.14.0_to_1.0.0` upgrade script makes `cryptographic_binding_methods_supported` and `proof_types_supported` nullable in `certify.credential_config`; NULL marks a configuration without holder binding. Existing configurations are unchanged.

The rollback script restores `NOT NULL`. It first gives every unbound configuration the 1.0.0 defaults: `cose_key` for `mso_mdoc`, `did:jwk` and `did:key` for other formats, and the `jwt` proof type with `RS256`, `ES256`, `PS256` and `EdDSA`. After a rollback these configurations are holder-bound again.
