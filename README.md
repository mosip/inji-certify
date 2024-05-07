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
    cd inji-certify
    ```
2. Change the value of `WEB_DID_BASE_URL` in [.env](docker-compose-sunbird/.env) file to your public domain where did.json will be hosted(You can use your github profile to host DIDs).

3. Execute the installation script:

    ```bash
    ./install.sh
    ```

4. During the execution of the `install.sh` script, user will be prompted to select the service to be installed:

    ```
    1. Sunbird RC
    2. Esignet
    0. Exit
    Select:
    ```

5. Select "Sunbird RC" as the first step of the installation process.

6. The installation will encompass the following services:
   * [Credential Schema](https://github.com/Sunbird-RC/sunbird-rc-core/tree/main/services/credential-schema)
   * [Credential Service](https://github.com/Sunbird-RC/sunbird-rc-core/tree/main/services/credentials-service)
   * [Identity Service](https://github.com/Sunbird-RC/sunbird-rc-core/tree/main/services/identity-service)
   * [Registry](https://github.com/Sunbird-RC/sunbird-rc-core)
7. Post Sunbird installation, proceed to create an issuer and credential schema. Refer to the Postman collections available [here](https://github.com/Sunbird-RC/demo-mosip-rc/blob/main/Demo%20Mosip%20RC.postman_collection.json).
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
8. Add the jar file of Digital Credential Stack(DCS) plugin implementation in [loader_path](docker-compose-esignet/loader_path). The JAR can be built [from source](https://github.com/mosip/digital-credential-plugins/) or [downloaded directly](https://mvnrepository.com/artifact/io.mosip.esignet.sunbirdrc/sunbird-rc-esignet-integration-impl).
9. Modify the properties of the Esignet service located in the [esignet-default.properties](docker-compose-esignet/config/esignet-default.properties) file:
   - Include Issuer ID and credential schema ID for the following properties: `mosip.esignet.vciplugin.sunbird-rc.credential-type.{credential type}.static-value-map.issuerId`, `mosip.esignet.vciplugin.sunbird-rc.credential-type.{credential-type}.cred-schema-id`.
   - The `$.schema[0].author` DID goes to the config ending in issuerId and `$.schema[0].id` DID goes to the config ending in `cred-schema-id`.
10. Once the Esignet properties are configured, proceed to select Esignet from the options provided for eSignet.
11. Download the postman collection and environment for sunbird use case from [here](https://github.com/mosip/digital-credential-plugins/tree/master/sunbird-rc-esignet-integration-impl/postman-collections).
12. Create Client from Create OIDC client API, add redirect uri 'http://localhost:3001', add auth-factor 'mosip:idp:acr:knowledge' to the request body.
13. Change `aud` variable in environment to 'http://localhost:8088/v1/esignet/oauth/v2/token' and set `audUrl` to http://localhost:8088
14. Perform a Knowledge based authentication(KBA) as specified in the Postman collection.
    * perform the authorize callback request
    * in the /authorization/authenticate request update the challenge to a URL-safe base64 encoded string with the KBA details such as `{"fullName":"Abhishek Gangwar","dob":"1967-10-24"}`, one can use an [online base64 encoding service](https://base64encode.org) for the same.
    * in the /vci/credential api inside pre-request script section:
      * change the aud env variable to  -> "aud" : pm.environment.get('audUrl')
      * For generating a credential with smaller VC change the below variables:
        * `keypair` variable to -> keyPair = pmlib.rs.KEYUTIL.generateKeypair("EC", "P-256");
        * `alg` to ES256 in place of RS256
 

## Properties for custom use case

- Sample schemas for Insurance registry are provided [here](docker-compose-sunbird/schemas), change it according to use case.
- Change these properties for different use case `mosip.esignet.authenticator.sunbird-rc.auth-factor.kba.field-details`,`mosip.esignet.authenticator.sunbird-rc.auth-factor.kba.individual-id-field`
- Add the Sunbird registry URL for these properties: `mosip.esignet.vciplugin.sunbird-rc.issue-credential-url`,`mosip.esignet.authenticator.sunbird-rc.auth-factor.kba.registry-search-url`.
- Specify the list of supported credential types using the property: `mosip.esignet.vciplugin.sunbird-rc.supported-credential-types`.
- For each supported credential type change the below properties. Sample properties are provided in the [default properties](docker-compose-esignet/config/esignet-default.properties) file.
   * Issuer id `mosip.esignet.vciplugin.sunbird-rc.credential-type.{credential type}.static-value-map.issuerId`
   * Credential schema id `mosip.esignet.vciplugin.sunbird-rc.credential-type.{credential type}.cred-schema-id`
   * Registry Url `mosip.esignet.vciplugin.sunbird-rc.credential-type.{credential type}.registry-get-url`
   * Template Url `mosip.esignet.vciplugin.sunbird-rc.credential-type.{credential type}.template-url`
   * Credential schema version `mosip.esignet.vciplugin.sunbird-rc.credential-type.{credential type}.cred-schema-version`
- Define the list of supported scopes using: `mosip.esignet.supported.credential.scopes`, and for each scope, map the resource accordingly at `mosip.esignet.credential.scope-resource-mapping`.
- Change this property for different credential types supported `mosip.esignet.vci.key-values` based on OID4VCI version.

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
