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

# Changes in release 1.0.0-rc.2

## Credential configuration metadata attributes are mandatory

`cryptographicBindingMethodsSupported`, `credentialSigningAlgValuesSupported` and `proofTypesSupported` are now mandatory in the Add (`POST /credential-configurations`) and Update (`PUT /credential-configurations/{credentialConfigKeyId}`) requests. A request that leaves one out, sends it as `null` or sends it empty is rejected with `invalid_request`, and nothing is filled in from the deployment properties any more.

**Action for existing automation:** every Update request must send all three attributes, even one that only changes an unrelated field such as the display name. This includes configurations created before these attributes were stored. Existing configurations keep advertising the same values without being re-submitted; the Get response returns those values, which can be sent back unchanged.

See [Credential Issuer Configuration](./Credential_Issuer_Configuration.md) for the validation rules.
