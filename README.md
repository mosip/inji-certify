# Inji Certify

INJI Certify enables an issuer to connect with an existing Credential Registry to issue verifiable credentials.
Issuer can configure their respective credential schema for various types of certificates they wish to issue. Certificates are generated in JSON-LD as per W3C VC v1.1.


# API docs

- Link to [Stoplight](https://mosip.stoplight.io/docs/inji-certify/25f435617408e-inji-certify)

# Requirements to run it locally (with docker compose)

Instructions [here](./docker-compose/docker-compose-injistack/README.md).

### Steps to configure postgres-dataprovider-plugin
- Supported versions: 0.3.0 and above
- Download the latest JAR from:
  ```
  https://repo1.maven.org/maven2/io/mosip/certify/postgres-dataprovider-plugin/0.3.0/postgres-dataprovider-plugin-0.3.0.jar
  ```
- Refer to the documentation of postgres plugin for required configurations: [Postgres Plugin Doc](https://github.com/mosip/digital-credential-plugins/blob/v0.3.0/postgres-dataprovider-plugin/README.md)

### For Advanced Users: Create Custom Plugin

You can create your own plugin by implementing the following interface and refer the below for postgres-dataprovider-plugin implementation:

Reference Implementation: [postgres-dataprovider-plugin](https://github.com/mosip/digital-credential-plugins/tree/release-0.3.x/postgres-dataprovider-plugin).

```java
public interface DataProviderPlugin {
    // Implement your custom logic here
}
```

## Databases

Refer to [SQL scripts](db_scripts) and go through it's README

## Rendering Template
Refer to [Rendering Template](docs/Rendering-Template.md)

# Local Installation Guide (via Docker Compose)

The following steps will help you to setup Sunbird RC and Esignet services using Docker compose alongwith Certify.

## Helm Deployments

* The links for installation through helm can be found here
   * Sunbird services
      *  [Registry](https://github.com/challabeehyv/sunbird-devops/tree/main/deploy-as-code/helm/demo-mosip-registry)
      *  [Credential service, Credential schema service & Identity service](https://github.com/Sunbird-RC/devops/tree/main/deploy-as-code/helm/v2)
      *  [Vault](https://github.com/challabeehyv/sunbird-devops/blob/main/deploy-as-code/helm/v2/README.md#vault-deployment)
   * [Esignet](https://github.com/mosip/esignet/tree/v1.4.1/helm)
   * [Certify](https://github.com/mosip/inji-certify/tree/v0.9.1/helm/inji-certify)
