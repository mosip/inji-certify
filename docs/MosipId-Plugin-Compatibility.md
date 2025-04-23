# MOSIP Identity Certify Plugin - eSignet Compatibility and Deployment Guide

This document provides guidance on selecting the correct version of the `mosip-identity-certify-plugin` based on your `eSignet` version requirements and how to deploy it, particularly in a Kubernetes environment.

## eSignet Version Compatibility

Choose the plugin version that matches the `eSignet` version you need to interact with:

1.  **For compatibility with eSignet v1.4.1:**
    * You need to use `mosip-identity-certify-plugin` version **0.3.0**.
    * You can download the required JAR file directly from Maven Central:
        ```
        [https://repo1.maven.org/maven2/io/mosip/certify/mosip-identity-certify-plugin/0.3.0/mosip-identity-certify-plugin-0.3.0.jar](https://repo1.maven.org/maven2/io/mosip/certify/mosip-identity-certify-plugin/0.3.0/mosip-identity-certify-plugin-0.3.0.jar)
        ```

2.  **For compatibility with eSignet v1.5.1:**
    * You should use the latest release of the plugin, version **0.4.0**.
    * This version **is already included** in the following Docker image:
        ```
        mosipqa/inji-certify-with-plugins:0.11.x
        ```
    * If you are using this Docker image or a later compatible version, no separate plugin installation is required for eSignet 1.5.1 compatibility.

## Kubernetes Deployment (for Plugin v0.3.0)

If you need to use `mosip-identity-certify-plugin` version **0.3.0** (for eSignet 1.4.1 compatibility) within a Kubernetes deployment that doesn't already include it (e.g., if you are *not* using the `mosipqa/inji-certify-with-plugins:0.11.x` image or need the older plugin), you can make the JAR available to your application container using one of the following methods:

1.  **Using an Init Container:**
    * Define an `initContainer` in your Pod specification.
    * This container can download the `mosip-identity-certify-plugin-0.3.0.jar` (e.g., using `wget` or `curl`) or copy it from a known location.
    * Mount a shared `emptyDir` volume to both the `initContainer` and your main application container.
    * The `initContainer` places the JAR file into the shared volume.
    * The main container can then access the JAR from the mounted volume path once it starts.

2.  **Using a Volume Mount:**
    * Download the `mosip-identity-certify-plugin-0.3.0.jar` beforehand.
    * Make the JAR file available through a Kubernetes volume. This could be:
        * A `hostPath` volume (if the JAR is placed on the node - simpler but less flexible).
        * A `persistentVolumeClaim` (if the JAR is stored on persistent storage).
        * Potentially baked into a custom image layer or mounted via a `ConfigMap` (though ConfigMaps have size limits and are less ideal for binary JARs).
    * Mount this volume into your application container at the location where the application expects to find its plugins.

Choose the method that best suits your cluster configuration and deployment strategy. Using the pre-built `mosipqa/inji-certify-with-plugins:0.11.x` image is the simplest approach when eSignet 1.5.1 compatibility is required.