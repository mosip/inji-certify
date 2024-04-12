# inji-certify
INJI Certify enables an issuer to connect with an existing database in order to issue verifiable credentials.
It assumes the source database has a primary key for each data record and information required to authenticate a user (e.g. phone, email, or other personal information).
Issuer can configure multiple credential schema for various types of certificates they wish to issue. Certificates are generated in JSON-LD as per W3C VC v1.1.

## Installation Guide

The following steps will help you to setup Sunbird RC and Esignet services using Docker compose.

## Requirements

* Docker
* Docker Compose

## Installation

Execute installation script
1. Sample schemas for registry are provided [here](docker-compose-sunbird/schemas), change it according to use case.
2. Clone the repository and navigate to its directory:

    ```bash
    cd inji-certify
    ./script.sh
    ```
   
3. During the execution of the `script.sh` script, user will be prompted to select the service to be installed:

    ```
    1. Sunbird RC
    2. Esignet
    0. Exit
    Select: 
    ```

4. Select "Sunbird RC" as the first step of the installation process.

5. The installation will encompass the following services:

    * [Credential Schema](https://github.com/Sunbird-RC/sunbird-rc-core/tree/main/services/credential-schema)
    * [Credential Service](https://github.com/Sunbird-RC/sunbird-rc-core/tree/main/services/credentials-service)
    * [Identity Service](https://github.com/Sunbird-RC/sunbird-rc-core/tree/main/services/identity-service)
    * [Registry](https://github.com/Sunbird-RC/sunbird-rc-core)
6. Post Sunbird installation, proceed to create an issuer and credential schema. Refer to the API schemas available [here](https://github.com/Sunbird-RC/sunbird-rc-core/tree/main/api-documentation).
7. Add the jar file of Digital Credential Stack(DCS) plugin implementation in [loader_path](docker-compose-esignet/loader_path) the GitHub link for the repository can be found [here](https://github.com/mosip/digital-credential-plugins).
8. Modify the properties of the Esignet service located in the [esignet-default.properties](docker-compose-esignet/config/esignet-default.properties) file:

    - Include Issuer ID and credential schema ID for the following properties: `mosip.esignet.vciplugin.sunbird-rc.credential-type.{credential type}.static-value-map.issuerId`, `mosip.esignet.vciplugin.sunbird-rc.credential-type.{credential-type}.cred-schema-id`.
    - Add the Sunbird registry URL for these properties: `mosip.esignet.vciplugin.sunbird-rc.issue-credential-url`,`mosip.esignet.authenticator.sunbird-rc.auth-factor.kba.registry-search-url`.
    - Specify the list of supported credential types using the property: `mosip.esignet.vciplugin.sunbird-rc.supported-credential-types`.
    - For each supported credential type, provide Template URL, schema ID, issuer ID, registry URL, and credential schema version. Sample properties are provided in the default properties file.
    - Define the list of supported scopes using: `mosip.esignet.supported.credential.scopes`, and for each scope, map the resource accordingly at `mosip.esignet.credential.scope-resource-mapping`.

9. Once the Esignet properties are configured, proceed to select Esignet from the options provided for installation steps.

## Helm Deployments

* The links for installation through helm can be found here
   * Sunbird services
      *  [Registry](https://github.com/challabeehyv/sunbird-devops/tree/main/deploy-as-code/helm/demo-mosip-registry)
      *  [Credential service, Credential schema service & Identity service](https://github.com/Sunbird-RC/devops/tree/main/deploy-as-code/helm/v2)
      *  [Vault](https://github.com/challabeehyv/sunbird-devops/blob/main/deploy-as-code/helm/v2/README.md#vault-deployment)
   * [Esignet](https://github.com/mosip/esignet/tree/develop/helm) 