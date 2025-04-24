# README: Removing External Artifactory Dependency in Inji Certify (v0.11.x+)

## Overview

Starting with version `0.11.x`, Inji Certify has been updated to remove the runtime dependency on an external Artifactory server. This change simplifies deployment, reduces reliance on external service during startup.

Key components like standard plugins and HSM client libraries are now handled differently: either bundled directly into specific Docker images or managed via volume mounts during deployment.

## Key Changes

1.  **Artifactory URL Removed:** The `artifactory_url_env` environment variable and the associated logic for downloading plugins at runtime from `configure_start.sh` have been removed.
2.  **Glowroot APM Dependency Removed:** The `is_glowroot_env` 
3.  **HSM Client Bundled at Build Time:** The standard HSM `client.zip` is now included directly within the Docker image during the build process, instead of being downloaded at runtime.
4.  **Introduction of Two Docker Image Variants:** To cater to different needs, two distinct Docker images are now published:
    *   `inji-certify:0.11.x`: The base image **without** any plugins bundled.
    *   `inji-certify-with-plugins:0.11.x`: This image includes the base application **plus** a set of standard plugins pre-bundled.
5.  **[Custom Plugin Loading](./Custom-Plugin-K8s.md):** Custom plugins must now be provided to the container using standard Kubernetes volume mounting techniques. The application is configured to load plugins from the `/home/mosip/additional_jars/` directory.

## Impact on Deployments

These changes require adjustments to how you deploy and configure Inji Certify:

*   **Configuration:** Remove `artifactory_url_env` and `is_glowroot_env` from your deployment configurations as they are no longer used.
*   **Choosing an Image:** Select the appropriate Docker image based on your plugin requirements:
    *   Use `inji-certify-with-plugins:0.11.x` if the bundled plugins meet your needs.
    *   Use `inji-certify:0.11.x` if you need a minimal base or prefer to manage all plugins (standard and custom) explicitly via volume mounts.
*   **Plugin Management:**
    *   If using `inji-certify-with-plugins:0.11.x` and you need *additional* custom plugins, mount your custom JARs into `/home/mosip/additional_jars/`.
    *   If using `inji-certify:0.11.x`, mount *all* required plugin JARs (standard and custom) into `/home/mosip/additional_jars/`.