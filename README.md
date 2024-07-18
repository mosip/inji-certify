# inji-certify
INJI Certify enables an issuer to connect with an existing database in order to issue verifiable credentials.
It assumes the source database has a primary key for each data record and information required to authenticate a user (e.g. phone, email, or other personal information).
Issuer can configure their respective credential schema for various types of certificates they wish to issue. Certificates are generated in JSON-LD as per W3C VC v1.1.

## Requirements
- Java SE 21
- Maven 

## Build
```shell
mvn clean install -Dgpg.skip=true
```
## Run
```shell
mvn spring-boot:run -Dspring.profiles.active=local
```
## Databases
Refer to [SQL scripts](db_scripts).

## Installation Guide

The following steps will help you to setup Sunbird RC and Esignet services using Docker compose.

## Requirements

* Docker (26.0.0)
* Docker Compose (2.25)


### Steps to setup Mock credential use case

1. Clone the repository and navigate to its directory:

    ```bash
    cd inji-certify/docker-compose/docker-compose-certify
    ```
2. Change the variable `active_profile_env` in [esignet](docker-compose/docker-compose-certify/docker-compose.yml#L80) and [certify](docker-compose/docker-compose-certify/docker-compose.yml#L104) to `active_profile_env=default,mock-identity`
3. Esignet and Certify takes the required plugin from artifactory server by default, in case there is a custom use case where plugin is to be added manually follow the below steps:
    * Create a folder with name loader_path [here](docker-compose/docker-compose-certify).
    * Add the jar file of Digital Credential Stack(DCS) plugin implementations for eSignet and certify:
      * For eSignet:
        * In the [docker compose file](docker-compose/docker-compose-certify/docker-compose.yml) comment the line [esignet_wrapper_url_env](docker-compose/docker-compose-certify/docker-compose.yml#L83)
        *  create a folder with name esignet inside loader_path folder created in the above step and add the jar files inside the folder.
        *  JAR file for mock identity can be downloaded [here](https://repo1.maven.org/maven2/io/mosip/esignet/mock/mock-esignet-integration-impl/0.9.2/mock-esignet-integration-impl-0.9.2.jar)
      * For certify:
        * In the [docker compose file](docker-compose/docker-compose-certify/docker-compose.yml) uncomment the [enable_certify_artifactory](docker-compose/docker-compose-certify/docker-compose.yml#L107) and [volume](docker-compose/docker-compose-certify/docker-compose.yml#L113)
        * create a folder with name certify inside loader_path folder created in the above step and add the jar file inside the folder. 
        * The JAR can be built [from source](https://github.com/mosip/digital-credential-plugins/tree/develop/mock-certify-plugin).
4. Execute the installation script

    ```bash
    ./install.sh
    ```

5. During the execution of the `install.sh` script, user will be prompted to select the service to be installed:

    ```
    1. Sunbird RC
    2. Certify
    0. Exit
    Select:
    ```

6. Select "Certify" from the choices provided.
7. The installation of Certify will encompass the following services:
    * [Esignet Service](https://github.com/mosip/esignet)
    * [Certify Service](https://github.com/mosip/inji-certify)
8. Download the postman collection and environment for mock use case from [here](docker-compose/docker-compose-certify/postman-collections/mock).
9. Create Client from Create OIDC client API.
10. Create a mock identity with Create Mock Identity API in the Mock Identity System folder.
11. Change the `individualId` variable in environment to the above created mock identity identifier.
12. Perform a Mock Authentication with the API's in `VCI` folder as specified in the Postman collection.


### Steps to setup Insurance credential use case

Execute installation script

1. Clone the repository and navigate to its directory:

    ```bash
    cd inji-certify/docker-compose
    ./install.sh
    ```

2. During the execution of the `install.sh` script, user will be prompted to select the service to be installed:

    ```
    1. Sunbird RC
    2. Certify
    0. Exit
    Select:
    ```

3. Select "Sunbird RC" as the first step of the installation process.

4. The installation will encompass the following services:
   * [Credential Schema](https://github.com/Sunbird-RC/sunbird-rc-core/tree/main/services/credential-schema)
   * [Credential Service](https://github.com/Sunbird-RC/sunbird-rc-core/tree/main/services/credentials-service)
   * [Identity Service](https://github.com/Sunbird-RC/sunbird-rc-core/tree/main/services/identity-service)
   * [Registry](https://github.com/Sunbird-RC/sunbird-rc-core)
5. Post Sunbird installation, proceed to create an issuer and credential schema. Refer to the API schemas available [here](https://github.com/Sunbird-RC/sunbird-rc-core/tree/main/api-documentation).
    * Set the hostname of the endpoints correctly as per your docker setup
    * Now generate a DID, create a credential schema and create an issuance registry
        * take note of `$.schema[0].author`  and  `$.schema[0].id` from the create credential schema request
6. Change the variable `active_profile_env` in [esignet](docker-compose/docker-compose-certify/docker-compose.yml#L80) and [certify](docker-compose/docker-compose-certify/docker-compose.yml#L104) to `active_profile_env=default,sunbird-insurance`
7. Esignet and Certify takes the required plugin from artifactory server by default, in case there is a custom use case where plugin is to be added manually follow the below steps:
    * Create a folder with name loader_path [here](docker-compose/docker-compose-certify).
    * Add the jar file of Digital Credential Stack(DCS) plugin implementations for eSignet and certify:
      * For eSignet:
          *  In the [docker compose file](docker-compose/docker-compose-certify/docker-compose.yml) comment the line [esignet_wrapper_url_env](docker-compose/docker-compose-certify/docker-compose.yml#L82)
          *  create a folder with name esignet inside loader_path folder created in the above step and add the jar files inside the folder.
          *   JAR file for sunbird can be downloaded [here](https://mvnrepository.com/artifact/io.mosip.esignet.sunbirdrc/sunbird-rc-esignet-integration-impl).
      * For certify:
          * In the [docker compose file](docker-compose/docker-compose-certify/docker-compose.yml) uncomment the [enable_certify_artifactory](docker-compose/docker-compose-certify/docker-compose.yml#L106) and [volume](docker-compose/docker-compose-certify/docker-compose.yml#L113)
          * create a folder with name certify inside loader_path folder created in the above step and add the jar file inside the folder.
          * The JAR can be built [from source](https://github.com/mosip/digital-credential-plugins/tree/develop/sunbird-rc-certify-integration-impl).
8. Modify the properties of the Esignet and Certify services located in the [esignet-sunbird-insurance.properties](docker-compose/docker-compose-certify/config/esignet-sunbird-insurance.properties) and [certify-sunbird-insurance.properties](docker-compose/docker-compose-certify/config/certify-sunbird-insurance.properties) files respectively.
   - Include Issuer ID and credential schema ID for the following properties: 
     - esignet-default-properties:
       - `mosip.esignet.vciplugin.sunbird-rc.credential-type.{credential type}.static-value-map.issuerId`.
       - `mosip.esignet.vciplugin.sunbird-rc.credential-type.{credential-type}.cred-schema-id`.
     - certify-default.properties:
       - `mosip.certify.vciplugin.sunbird-rc.credential-type.{credential type}.static-value-map.issuerId`.
       - `mosip.certify.vciplugin.sunbird-rc.credential-type.{credential-type}.cred-schema-id`.
   - The `$.schema[0].author` DID goes to the config ending in issuerId and `$.schema[0].id` DID goes to the config ending in `cred-schema-id`.
9. Once the Esignet and Certify properties are configured, proceed to select Certify from the option provided in the installation steps.
10. The installation of Certify will encompass the following services:
    * [Esignet Service](https://github.com/mosip/esignet)
    * [Certify Service](https://github.com/mosip/inji-certify)
11. Download the postman collection and environment for sunbird use case from [here](docker-compose/docker-compose-certify/postman-collections/sunbird).
12. Create Client from Create OIDC client API.
13. Perform a Knowledge based authentication(KBA) as specified in the Postman collection.
    * perform the authorize callback request
    * in the /authorization/authenticate request update the challenge to a URL-safe base64 encoded string with the KBA details such as `{"fullName":"Abhishek Gangwar","dob":"1967-10-24"}`, one can use an [online base64 encoding service](https://base64encode.org) for the same.

## Properties for custom use case

- Sample schemas for Insurance registry are provided [here](docker-compose/docker-compose-sunbird/schemas), change it according to use case.
- Change these properties for different use case `mosip.esignet.authenticator.sunbird-rc.auth-factor.kba.field-details`,`mosip.esignet.authenticator.sunbird-rc.auth-factor.kba.individual-id-field`
- Add the Sunbird registry URL for these properties: `mosip.esignet.vciplugin.sunbird-rc.issue-credential-url`,`mosip.esignet.authenticator.sunbird-rc.auth-factor.kba.registry-search-url`.
- Specify the list of supported credential types for these properties:
  - esignet-default-properties:
    - `mosip.esignet.vciplugin.sunbird-rc.supported-credential-types`.
  - certify-default.properties:
    - `mosip.certify.vciplugin.sunbird-rc.supported-credential-types`.
- For each supported credential type change the below properties. Sample properties are provided in the [eSignet default properties](docker-compose/docker-compose-certify/config/esignet-default.properties) and [Certify default properties](docker-compose/docker-compose-certify/config/certify-default.properties).
  * esignet-default-properties:
    * Issuer id `mosip.esignet.vciplugin.sunbird-rc.credential-type.{credential type}.static-value-map.issuerId`
    * Credential schema id `mosip.esignet.vciplugin.sunbird-rc.credential-type.{credential type}.cred-schema-id`
    * Registry Url `mosip.esignet.vciplugin.sunbird-rc.credential-type.{credential type}.registry-get-url`
    * Template Url `mosip.esignet.vciplugin.sunbird-rc.credential-type.{credential type}.template-url`
    * Credential schema version `mosip.esignet.vciplugin.sunbird-rc.credential-type.{credential type}.cred-schema-version`
    * Define the list of supported scopes using: `mosip.esignet.supported.credential.scopes`, and for each scope, map the resource accordingly at `mosip.esignet.credential.scope-resource-mapping`.
    * Change these properties for different credential types supported `mosip.esignet.vci.key-values` based on OID4VCI version.
  * certify-default-properties:
    * Issuer id  `mosip.certify.vciplugin.sunbird-rc.credential-type.{credential type}.static-value-map.issuerId`
    * Credential schema id  `mosip.certify.vciplugin.sunbird-rc.credential-type.{credential type}.cred-schema-id`
    * Registry Url `mosip.certify.vciplugin.sunbird-rc.credential-type.{credential type}.registry-get-url`
    * Template Url `mosip.certify.vciplugin.sunbird-rc.credential-type.{credential type}.template-url`
    * Credential schema version  `mosip.certify.vciplugin.sunbird-rc.credential-type.{credential type}.cred-schema-version`
    * Change these properties for different credential types supported `mosip.certify.key-values` based on OID4VCI version.

## Note
 - To test the Setup from UI we can configure a Client and Issuer in InjiWeb.
   * Setup [InjiWeb](https://github.com/mosip/inji-web/blob/qa-develop/README.md) and [Mimoto](https://github.com/mosip/mimoto/blob/release-0.13.x/docker-compose/README.md) in local.
   * Add an issuer to mimoto issuer config with `authorization_endpoint`, `credential_endpoint` and `.well-known` properties pointing to eSignet and certify installed above.
   * Add the private key from the OIDC client created in eSignet(collection to create a client can be found [here](docker-compose/docker-compose-certify/postman-collections)) to the p12 file in mimoto.
   * You will be able to see the newly created issuer in InjiWeb home page to download the credential.

 - For this release Mosip ID and Mock plugins are using eSignet DTO's due to shared redis cache dependency to resolve serialization issues, so eSignet image tag version in docker compose should be in consistent with Mock and Mosip ID pom dependency version.As of now we are using eSignet 1.4.0 in docker compose as well as plugins in artifactory
   - [Mosip ID](https://github.com/mosip/digital-credential-plugins/blob/a96fada5b8eefa00282cadab1c698f429223c0b3/mosip-identity-certify-plugin/pom.xml#L148)
   - [Mock](https://github.com/mosip/digital-credential-plugins/blob/a96fada5b8eefa00282cadab1c698f429223c0b3/mock-certify-plugin/pom.xml#L75)


 

## Troubleshooting

- Apple Silicon Mac users should export or set `DOCKER_DEFAULT_PLATFORM=linux/amd64` before running the `install.sh` and use GNU `sed` to run the script over BSD `sed`. A simple way to do it would be to replace all instances of `sed` in the script with `gsed`. The former change is required to bring-up Vault cleanly without any unsealing errors and the latter had to be done because `sed` scripts are usually not portable across platforms.
- Windows users should run this script from `git bash` shell as-is.
- All users should install [postman utility lib](https://joolfe.github.io/postman-util-lib/) to their Postman setup.


## Helm Deployments

* The links for installation through helm can be found here
   * Sunbird services
      *  [Registry](https://github.com/challabeehyv/sunbird-devops/tree/main/deploy-as-code/helm/demo-mosip-registry)
      *  [Credential service, Credential schema service & Identity service](https://github.com/Sunbird-RC/devops/tree/main/deploy-as-code/helm/v2)
      *  [Vault](https://github.com/challabeehyv/sunbird-devops/blob/main/deploy-as-code/helm/v2/README.md#vault-deployment)
   * [Esignet](https://github.com/mosip/esignet/tree/release-1.4.x/helm)
   * [Certify](https://github.com/mosip/inji-certify/tree/release-0.9.x/helm/inji-certify)