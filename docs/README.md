# Developer READMEs

- [Local Development](./Local-Development.md)
- [How to decide b/w VCIssuance & DataProviderPlugin while writing your own](./VCIssuance-vs-DataProvider.md)

# Integrator READMEs

# Changes in release 0.11.0

## Removal of  Artifactory dependency

```text
artifactory_url_env - this field is removed from configure_start.sh to remove dependency on artifactory
any new plugin to be added can be added by volume mount to loader_path

is_glowroot_env - this field is removed from configure_start.sh to remove dependency on glowroot apm

```
