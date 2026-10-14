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

# Changes in release 1.0.0-alpha.2

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

---

# Changes in release 1.0.0-rc.1

## Credential configuration metadata attributes are mandatory

`cryptographicBindingMethodsSupported`, `proofTypesSupported` and `signatureAlgo` are now mandatory in the Add (`POST /credential-configurations`) and Update (`PUT /credential-configurations/{credentialConfigKeyId}`) requests, for every credential format. A request that leaves one out, sends it as `null` or sends it empty is rejected, and nothing is filled in from the deployment properties any more. In particular, an `ldp_vc` configuration without `signatureAlgo` no longer takes the first algorithm declared for its crypto suite.

`credentialSigningAlgValuesSupported` is no longer part of the request; a value sent for it is ignored. What the credential issuer metadata advertises in `credential_signing_alg_values_supported` is derived from the configuration instead, so it is always what the credential is signed with:

- `ldp_vc` advertises its crypto suite, for example `Ed25519Signature2020`, as OpenID4VCI 1.0 Appendix A.1.2.2 requires, where it previously advertised a JWS algorithm such as `EdDSA`. Existing `ldp_vc` configurations advertise their crypto suite without being re-submitted.
- `dc+sd-jwt` advertises its `signatureAlgo`, and `mso_mdoc` the COSE identifier of its `signatureAlgo`, as before.

`mso_mdoc` is signed with `signatureAlgo` alone, so it now requires `signatureAlgo` in place of `signatureCryptoSuite`, and a request that sends `signatureCryptoSuite` is rejected with `invalid_request`.

`mosip.certify.credential-config.credential-signing-alg-values-supported` can now be grouped by credential format, giving `mso_mdoc` and `dc+sd-jwt` their own list of allowed algorithms. The original shape, keyed by crypto suite only, is still read, so existing deployments need not change it.

**Action for existing automation:** every Update request must send both attributes and `signatureAlgo`, even one that only changes an unrelated field such as the display name. This includes configurations created before these attributes were stored. `credentialSigningAlgValuesSupported` can be dropped from requests, and `mso_mdoc` requests must drop `signatureCryptoSuite`.

See [Credential Issuer Configuration](./Credential_Issuer_Configuration.md) for the validation rules.
