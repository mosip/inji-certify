# Inji Certify

INJI Certify enables an issuer to connect with an existing Credential Registry to issue verifiable credentials.
Issuer can configure their respective credential schema for various types of certificates they wish to issue. Certificates are generated in JSON-LD as per W3C VC v1.1.


# API docs

- Link to [Stoplight](https://mosip.stoplight.io/docs/inji-certify/25f435617408e-inji-certify)

# Requirements to run it locally (with docker compose)

Instructions [here](./docker-compose/docker-compose-injistack/README.md).

## Databases

Refer to [SQL scripts](db_scripts) and go through it's README

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
