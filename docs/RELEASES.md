# Changes in release 0.11.0

## Removal of  Artifactory dependency

```text
artifactory_url_env - this field is removed from configure_start.sh to remove dependency on artifactory
any new plugin to be added can be added by volume mount to loader_path

is_glowroot_env - this field is removed from configure_start.sh to remove dependency on glowroot apm



```
moved client.zip to build time dependency in dockerfile - addition of new hsm-client zip can be done by adding it to volume mount in docker-compose or helm charts with same structure as [client.zip](https://raw.githubusercontent.com/mosip/artifactory-ref-impl/v1.3.0-beta.1/artifacts/src/hsm/client.zip)


# Note: MOSIP Identity Certify Plugin & eSignet Compatibility [Experimental]

This note provides specific version compatibility information between the official `mosip-identity-certify-plugin` and different versions of `eSignet`.

**Compatibility Summary:**

* **To work with eSignet `v1.4.1`:**
    * You **must** use `mosip-identity-certify-plugin` version `0.3.0`.
    * **Download Link:**
        ```
        [https://repo1.maven.org/maven2/io/mosip/certify/mosip-identity-certify-plugin/0.3.0/mosip-identity-certify-plugin-0.3.0.jar](https://repo1.maven.org/maven2/io/mosip/certify/mosip-identity-certify-plugin/0.3.0/mosip-identity-certify-plugin-0.3.0.jar)
        ```
    * If deploying this version in Kubernetes, you will need to add the JAR to your application container using methods like an Init Container or a Volume Mount (refer to general [Kubernetes plugin deployment guides](./Custom-Plugin-K8s.md)).

* **To work with eSignet `v1.5.1`:**
    * You should use `mosip-identity-certify-plugin` version `0.4.0`.
    * **Bundled Image:** This version (`0.4.0`) is conveniently **pre-included** in the following Docker image:
        ```
        mosipqa/inji-certify-with-plugins:0.11.x
        ```
    * If you are using this Docker image (or a later compatible version), no separate installation or addition of the `mosip-identity-certify-plugin` v0.4.0 JAR is typically required.

**Important:** Always ensure the plugin version you deploy matches the requirements of the target `eSignet` version you intend to integrate with. Using incompatible versions will likely lead to errors.
