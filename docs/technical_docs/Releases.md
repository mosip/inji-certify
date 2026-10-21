# Changes in release 0.11.0

## Removal of  Artifactory dependency

```text
artifactory_url_env - this field is removed from configure_start.sh to remove dependency on artifactory
any new plugin to be added can be added by volume mount to loader_path

is_glowroot_env - this field is removed from configure_start.sh to remove dependency on glowroot apm



```
moved client.zip to build time dependency in dockerfile - addition of new hsm-client zip can be done by adding it to volume mount in docker-compose or helm charts with same structure as [client.zip](https://raw.githubusercontent.com/mosip/artifactory-ref-impl/v1.3.0-beta.1/artifacts/src/hsm/client.zip)

---

# Changes in release 0.12.0

## Restructure of credential_template table

Step-by-Step Migration guide for upgrade from 0.11.0 to 0.12.0 is available at [Migration Guide](./Migration_Guide_0.11.0_To_0.12.0.md)

---

# Changes in release 1.0.0-rc.1

## Velocity upgraded from 1.7 to 2.4.1: template behaviour changes

Credential templates (`vc_template`) are now rendered with Velocity 2.4.1. This fixes CVE-2020-13936.

**1. `#if` treats empty values as false**

| `phone` value | Before (1.7) | After (2.4.1) |
|---|---|---|
| `"+91..."` | included | included |
| `""` | `"phone": ""` included | **omitted** |
| null | omitted | omitted |

If a field must always appear, use `#if($var || $var == '')`, or drop the `#if` and use `$!{var}`.

**2. Loop variables renamed**

Replace `$velocityCount` with `$foreach.count`, and `$velocityHasNext` with `$foreach.hasNext`.

**3. Reflection blocked**

`SecureUberspector` is enabled. Templates can no longer call methods on classes like `Class`, `ClassLoader`, `Runtime` or `System`, so `$x.getClass().forName(...)` no longer works. Normal field access and the `$_dateTool` and `$_esc` tools are unaffected.

## Credential configuration metadata attributes are mandatory

`cryptographicBindingMethodsSupported`, `proofTypesSupported` and `signatureAlgo` are now mandatory in the Add (`POST /credential-configurations`) and Update (`PUT /credential-configurations/{credentialConfigKeyId}`) requests, for every credential format. A request that leaves one out, sends it as `null` or sends it empty is rejected, and nothing is filled in from the deployment properties any more. In particular, an `ldp_vc` configuration without `signatureAlgo` no longer takes the first algorithm declared for its crypto suite. `signatureAlgo` is mandatory in DataProvider plugin mode only: in VCIssuance plugin mode the plugin signs the credential, so it is optional, but a value that is sent is validated in both modes.

| Format | Plugin mode | `signatureAlgo` | `signatureCryptoSuite` | `credential_signing_alg_values_supported` |
|---|---|---|---|---|
| `ldp_vc` | DataProvider | Required | Required | The suite, e.g. `["Ed25519Signature2020"]` |
| `ldp_vc` | VCIssuance | Not required, validated if sent | Required | The suite, e.g. `["Ed25519Signature2020"]` |
| `mso_mdoc` | DataProvider | Required | Not required, ignored and not stored | COSE number of the algorithm, e.g. `[-7]` for `ES256` |
| `mso_mdoc` | VCIssuance | Not required, validated if sent | Not required, ignored and not stored | COSE number if set, e.g. `[-7]`. Omitted if null. |
| `dc+sd-jwt` | DataProvider | Required | Must not be sent (the request is rejected) | The algorithm, e.g. `["ES256"]` |
| `dc+sd-jwt` | VCIssuance | Not required, validated if sent | Must not be sent | The algorithm if set. Omitted if null. |

The plugin mode comes from `mosip.certify.plugin-mode`, not from the request.

`credentialSigningAlgValuesSupported` is no longer part of the request; a request that still sends it is rejected with `invalid_request` as an unrecognised field. What the credential issuer metadata advertises in `credential_signing_alg_values_supported` is derived from the configuration instead, so it is always what the credential is signed with:

- `ldp_vc` advertises its crypto suite, for example `Ed25519Signature2020`, as OpenID4VCI 1.0 Appendix A.1.2.2 requires ([#1110](https://github.com/inji/inji-certify/issues/1110)), where it previously advertised a JWS algorithm such as `EdDSA`.
- `dc+sd-jwt` advertises its `signatureAlgo`, and `mso_mdoc` the COSE identifier of its `signatureAlgo`, as before.

Nothing is resolved from the properties for it any more. Existing configurations advertise their own signing algorithm (or crypto suite for `ldp_vc`) without being re-submitted.

`mso_mdoc` is signed with `signatureAlgo` alone, so it now requires `signatureAlgo` in DataProvider plugin mode (optional in VCIssuance mode), and `signatureCryptoSuite` is optional. If one is sent for `mso_mdoc`, its value is not validated, and it is not stored.

**Action for existing deployments:** add `jwk` to the `ldp_vc` and `dc+sd-jwt` entries of `mosip.certify.credential-config.cryptographic-binding-methods-supported`. The previous release declared only `did:jwk` and `did:key`, so a configuration that selects `jwk` is rejected until it is added:

```properties
mosip.certify.credential-config.cryptographic-binding-methods-supported={\
  'ldp_vc': {'jwk','did:jwk','did:key'},\
  'mso_mdoc': {'cose_key'},\
  'dc+sd-jwt': {'jwk','did:jwk','did:key'}\
}
```

**Action for existing automation:** every Update request must send both attributes, and `signatureAlgo` in DataProvider plugin mode, even one that only changes an unrelated field such as the display name. This includes configurations created before these attributes were stored. `credentialSigningAlgValuesSupported` must be removed from every request body.

See [Credential Issuer Configuration](./Credential_Issuer_Configuration.md) for the validation rules.
