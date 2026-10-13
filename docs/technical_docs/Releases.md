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
