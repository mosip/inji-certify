# inji-certify
INJI Certify enables an issuer to connect with an existing database in order to issue verifiable credentials.
It assumes the source database has a primary key for each data record and information required to authenticate a user (e.g. phone, email, or other personal information).
Issuer can configure their respective credential schema for various types of certificates they wish to issue. Certificates are generated in JSON-LD as per W3C VC v1.1.

## Installation Guide

The following steps will help you to setup Sunbird RC and Esignet services using Docker compose.

## Requirements

* Docker (26.0.0)
* Docker Compose (2.25)

## Installation

### Steps to setup Insurance credential use case

Execute installation script

1. Clone the repository and navigate to its directory:

    ```bash
    cd inji-certify/docker-compose
    ./install.sh
    ```
2. Change the value of `WEB_DID_BASE_URL` in [.env](docker-compose-sunbird/.env) file to your public domain where did.json will be hosted(You can use your github profile to host DIDs).

3. During the execution of the `install.sh` script, user will be prompted to select the service to be installed:

    ```
    1. Sunbird RC
    2. Certify
    0. Exit
    Select:
    ```

4. Select "Sunbird RC" as the first step of the installation process.

5. The installation will encompass the following services:
   * [Credential Schema](https://github.com/Sunbird-RC/sunbird-rc-core/tree/main/services/credential-schema)
   * [Credential Service](https://github.com/Sunbird-RC/sunbird-rc-core/tree/main/services/credentials-service)
   * [Identity Service](https://github.com/Sunbird-RC/sunbird-rc-core/tree/main/services/identity-service)
   * [Registry](https://github.com/Sunbird-RC/sunbird-rc-core)
     
6. Post Sunbird installation, proceed to create an issuer and credential schema. Refer to the Postman collections available [here](https://github.com/Sunbird-RC/demo-mosip-rc/blob/main/Demo%20Mosip%20RC.postman_collection.json).
    * Set the hostname of the endpoints correctly as per your docker setup
    * For generating a DID use the `Generate a DID` API:
      * Change the `method` field in request body to `web` and `services` to an empty list
      * Take note of the `id` field from the API response.
      *  For local testing:
        * Inside the github repo mentioned in point 2, create a folder with the name of the unique id from the `id` field.
          * Example: If the `id` from the response is `did:web:challabeehyv.github.io:DID-Resolve:3313e611-d08a-49c8-b478-7f55eafe62f2` then the folder name should be `3313e611-d08a-49c8-b478-7f55eafe62f2`
        *  Create a file named did.json in the above folder and add the response from `Generate a DID` API.
        * Publish the did.json as a webpage.
        * Similarly multiple DIDs can be hosted in a single git repo with different folder names.
    * Now create a credential schema and create an issuance registry
         * take note of `$.schema[0].author`  and  `$.schema[0].id` from the create credential schema request
7. Create a folder with name loader_path [here](docker-compose/docker-compose-certify).
8. Add the jar file of Digital Credential Stack(DCS) plugin implementations for eSignet and certify:
     * For eSignet:
       * create a folder with name esignet inside loader_path folder created in the above step and add the jar files inside the folder.
       *  JAR file for sunbird can be downloaded [here](https://mvnrepository.com/artifact/io.mosip.esignet.sunbirdrc/sunbird-rc-esignet-integration-impl).
       *  JAR file for mock identity can be downloaded [here](https://repo1.maven.org/maven2/io/mosip/esignet/mock/mock-esignet-integration-impl/0.9.2/mock-esignet-integration-impl-0.9.2.jar)
     * For certify:
       * By default, the plugin will be taken from artifactory server
       * For custom plugin: Java 21 is needed 
         * In the [docker compose file](docker-compose/docker-compose-certify/docker-compose.yml) uncomment the [enable_certify_artifactory](docker-compose/docker-compose-certify/docker-compose.yml#L74) and [volume](docker-compose/docker-compose-certify/docker-compose.yml#L78)
         * create a folder with name certify inside loader_path folder created in the above step and add the jar file inside the folder. The JAR can be built [from source](https://github.com/mosip/digital-credential-plugins/tree/INJICERT-13/sunbird-rc-certify-integration-impl).
9. Modify the properties of the Esignet and Certify services located in the [esignet-default.properties](docker-compose/docker-compose-certify/config/esignet-default.properties) and [certify-default.properties](docker-compose/docker-compose-certify/config/certify-default.properties) files respectively.
   - Include Issuer ID and credential schema ID for the following properties: 
     - esignet-default-properties:
       - `mosip.esignet.vciplugin.sunbird-rc.credential-type.{credential type}.static-value-map.issuerId`.
       - `mosip.esignet.vciplugin.sunbird-rc.credential-type.{credential-type}.cred-schema-id`.
     - certify-plugin-default.properties:
       - `mosip.certify.vciplugin.sunbird-rc.credential-type.{credential type}.static-value-map.issuerId`.
       - `mosip.certify.vciplugin.sunbird-rc.credential-type.{credential-type}.cred-schema-id`.
   - The `$.schema[0].author` DID goes to the config ending in issuerId and `$.schema[0].id` DID goes to the config ending in `cred-schema-id`.
10. Once the Esignet and Certify properties are configured, proceed to select Certify from the option provided in the installation steps.
11. The installation of Certify will encompass the following services:
    * [Esignet Service](https://github.com/mosip/esignet)
    * [Certify Service](https://github.com/mosip/inji-certify)
12. Download the postman collection and environment for sunbird use case from [here](docker-compose/docker-compose-certify/postman-collections).
13. Create Client from Create OIDC client API, add redirect uri 'http://localhost:3001'.
14. Change `aud` variable in environment to 'http://localhost:8088/v1/esignet/oauth/v2/token' and set `audUrl` to http://localhost:8088
15. Perform a Knowledge based authentication(KBA) as specified in the Postman collection.
    * perform the authorize callback request
    * in the /authorization/authenticate request update the challenge to a URL-safe base64 encoded string with the KBA details such as `{"fullName":"Abhishek Gangwar","dob":"1967-10-24"}`, one can use an [online base64 encoding service](https://base64encode.org) for the same.
    * in the /issuance/credential api inside pre-request script section change the aud env variable to  -> "aud" : pm.environment.get('audUrl')
    * For generating a credential with smaller VC change the below variables:
        * `keypair` variable to -> keyPair = pmlib.rs.KEYUTIL.generateKeypair("EC", "P-256");
        * `alg` to ES256 in place of RS256

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
   * [Esignet](https://github.com/mosip/esignet/tree/develop/helm)
