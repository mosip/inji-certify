# Kubernetes Custom Plugin Deployment Guide for Inji Certify

This document outlines general methods for deploying **custom plugins** (packaged as JAR files) to your **Inji Certify container** within a Kubernetes environment, particularly when the plugin is not included in the base application image.

## Methods for Deploying Custom Plugins

You can make a custom plugin JAR available to your **Inji Certify container** using one of the following standard Kubernetes approaches:

1.  **Using an Init Container:**
    * **Concept:** An `initContainer` runs before your main **Inji Certify container** starts. It can prepare the environment, including fetching necessary files.
    * **Implementation:**
        * Define an `initContainer` in your Pod specification.
        * Configure this container to download your `custom-plugin.jar` (e.g., using `wget` or `curl` from an artifact repository or storage bucket) or copy it from another location accessible during initialization (like a pre-populated image layer).
        * Mount a shared `emptyDir` volume to both the `initContainer` and your main **Inji Certify container**.
        * The `initContainer` places the `custom-plugin.jar` file into this shared volume.
        * The main **Inji Certify container** starts after the `initContainer` completes successfully and can then access the JAR from the mounted volume path. Ensure your application is configured to load plugins from this specific path.

2.  **Using a Volume Mount:**
    * **Concept:** Directly mount a volume containing the plugin JAR into the **Inji Certify container**.
    * **Implementation:**
        * Ensure your `custom-plugin.jar` is available in a location accessible to Kubernetes volumes.
        * Make the JAR file available through a Kubernetes volume. Common options include:
            * A `persistentVolumeClaim` (PVC): Store the JAR on persistent, network-attached storage. This is suitable for larger files or when the JAR needs to persist across pod restarts independently of the node.
            * Baking the JAR into a custom application image layer: Include the JAR directly in the Docker image during the build process. This simplifies deployment but requires rebuilding the image to update the plugin.
            * A `hostPath` volume: Place the JAR directly on the node's filesystem. This is simple for single-node setups or testing but is less portable and not recommended for production clusters.
            * A `ConfigMap` or `Secret`: Suitable for very small JARs or configuration files, but generally not recommended for larger binary JARs due to size limits and potential encoding issues.
        * Mount the chosen volume into your **Inji Certify container** at the specific directory path where the application expects to find and load its plugins.

## Choosing a Method

* **Init Containers** are useful when the plugin needs to be fetched dynamically at deployment time or requires some setup.
* **Volume Mounts** (especially PVCs or baking into the image) are often preferred for stability and clearer dependency management, particularly if the plugin doesn't change frequently.

Remember to configure your application correctly to detect and load plugins from the path where you make the JAR available via the chosen method within the Inji Certify container.