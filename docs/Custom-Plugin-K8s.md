# Kubernetes Custom Plugin Deployment Guide for Inji Certify [Experimental]

This document outlines general methods for deploying **custom plugins** (packaged as JAR files) to your **Inji Certify container** within a Kubernetes environment, particularly when the plugin is not included in the base application image. The goal is to make these plugins available within the container at the path `/home/mosip/additional_jars/`.

## Methods for Deploying Custom Plugins

You can make a custom plugin JAR available to your **Inji Certify container** using one of the following standard Kubernetes approaches:

1.  **Using an Init Container:**
    * **Concept:** An `initContainer` runs before your main **Inji Certify container** starts. It can prepare the environment by fetching the plugin JAR and placing it into a shared volume.
    * **Implementation:**
        * Define an `initContainer` in your Pod specification.
        * Configure this container to download your `custom-plugin.jar` (e.g., using `wget` or `curl` from an artifact repository or storage bucket) or copy it from another location accessible during initialization.
        * Mount a shared `emptyDir` volume to both the `initContainer` (e.g., at a temporary path like `/staging`) and your main **Inji Certify container**, specifically mounting it at **`/home/mosip/additional_jars/`**.
        * The `initContainer` places the `custom-plugin.jar` file into this shared volume (e.g., copying it to `/staging/custom-plugin.jar`).
        * The main **Inji Certify container** starts after the `initContainer` completes successfully. It can then access the JAR directly at the path **`/home/mosip/additional_jars/custom-plugin.jar`**. Ensure your application is configured to load plugins from the **`/home/mosip/additional_jars/`** directory.

2.  **Using a Volume Mount:**
    * **Concept:** Directly mount a volume containing the plugin JAR into the **Inji Certify container** at the required path.
    * **Implementation:**
        * Ensure your `custom-plugin.jar` is available in a location accessible to Kubernetes volumes (like a PVC).
        * Make the JAR file available through a Kubernetes volume. Common options include:
            * A `persistentVolumeClaim` (PVC): Store the JAR on persistent, network-attached storage.
        * Mount the chosen volume (containing `custom-plugin.jar`) into your **Inji Certify container** specifically at the path **`/home/mosip/additional_jars/`**. The application should then find the plugin at `/home/mosip/additional_jars/custom-plugin.jar`.

3. **Rebuilding the image with the plugin:**
    * **Concept:** This method involves modifying the Dockerfile to include the plugin JAR directly in the image.
    * **Implementation:**
        * Add a line in your Dockerfile to copy the `custom-plugin.jar` into the image at the desired path (e.g., `/home/mosip/additional_jars/`).
        * Build and push the new image to your container registry.
        * Deploy this new image to your Kubernetes cluster.

## Choosing a Method

* **Init Containers** are useful when the plugin needs to be fetched dynamically at deployment time or requires some preparation before the main container starts.
* **Volume Mounts** (especially PVCs or baking into the image) are often preferred for stability and clearer dependency management, particularly if the plugin doesn't change frequently.

Remember to configure your application correctly to detect and load plugins specifically from the **`/home/mosip/additional_jars/`** path within the Inji Certify container, regardless of the deployment method chosen.
