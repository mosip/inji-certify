# Certify image with the DMT data provider

This runtime image includes both this fork's Certify service JAR and its DMT plugin JAR. It inherits the existing Certify base image's non-root user, Java runtime, startup script, and HSM support. Configuration and secrets are supplied at deployment time.

## Build

Run from the inji-certify repository root with Java 21:

```bash
mvn -B -ntp -pl certify-service,dmt-dataprovider-plugin -am install -Dgpg.skip=true
docker build -f certify-service-with-dmt/Dockerfile -t inji-certify-dmt:0.14.0 .
```

The Maven command runs tests. The Docker build packages the resulting artifacts without compiling source. Its Dockerfile-specific ignore file limits the build context to the service and plugin artifacts.

`CERTIFY_VERSION` selects the artifact filenames. `CERTIFY_BASE_IMAGE` selects the compatible Certify runtime image. For releases, pin the base image by digest in CI:

```bash
docker build -f certify-service-with-dmt/Dockerfile \
  --build-arg CERTIFY_VERSION=0.14.0 \
  --build-arg CERTIFY_BASE_IMAGE='injistack/inji-certify:0.14.0@sha256:<verified-digest>' \
  -t <registry>/inji-certify-dmt:<release> .
```

## Deploy

Supply the complete production Certify configuration through your existing configuration server or mount it under `/config/` and set `SPRING_CONFIG_ADDITIONAL_LOCATION=file:/config/`. Select the deployment profile with `SPRING_PROFILES_ACTIVE` and use `SPRING_CLOUD_CONFIG_URI` and `SPRING_CLOUD_CONFIG_LABEL` when using a configuration server. The image uses standard Spring configuration variables; legacy `active_profile_env` and `spring_config_url_env` variables are not used by its overridden command.

Include these DMT integration settings in that configuration:

```properties
mosip.certify.plugin-mode=DataProvider
mosip.certify.integration.data-provider-plugin=MasterDataProviderPlugin
mosip.certify.integration.scan-base-package=lk.gov.dmt.certify.plugin
```

Append any other required integration packages to the scan setting. Merge the plugin's `dmt-dataprovider-plugin/examples/application.yml` into the deployment configuration or import it explicitly. Supply `DMT_API_BASE_URL`, `DMT_IDENTITY_ISSUER`, and `DMT_API_KEY` using the deployment's configuration and secret mechanisms. Configure the production authentication issuer/JWKS, database, issuer signing keys, TLS trust, and ledger settings as well. Container `localhost` refers to the container itself; use reachable production service addresses.

Do not mount an empty directory over `/home/inji/additional_jars/`, because that would hide the packaged plugin. Register credential templates and metadata separately after startup. Publish the image to your registry and roll it out through the existing deployment; plugin updates require a new image and restart.

## Verify

Check service health, authentication against the configured JWKS endpoint, a DMT-backed issuance, the returned VC signature, and its ledger entry when the ledger is enabled. Use production-appropriate test records and credentials. The test kit's fixture keys, mock services, and `dmt-dev` configuration are not included in the image.
