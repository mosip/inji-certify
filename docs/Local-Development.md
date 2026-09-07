# Local Development of Inji Certify

**Pre-requisites**: 

- Java 21, Postgres DB installed & configured
- Git Bash for Windows users

1. Clone the repo, usually the active development happens on the `develop` branch but one can check out a tagged version as well.
2. Run the DB init scripts present in `db_scripts/inji_certify` , running `./deploy.sh deploy.properties` is a good way to init the DB.
3. Decide on the issuance mode of Certify. Some plugins enable Certify to operate as a Proxy and others enable it to work as an Issuer, configure `mosip.certify.plugin-mode` appropriately as `DataProvider` or `VCIssuance`.
    * [Recommended] Set it to `DataProvider` if you want a quickest possible working setup, and configure `mosip.certify.data-provider-plugin.issuer-uri` and `mosip.certify.data-provider-plugin.issuer-public-key-uri` appropriately.
    * If you have another Issuance module such as Sunbird, MOSIP Stack, you may want to set it up in `VCIssuance` mode.
4. Decide on the VCI plugin for use locally and configure it, while running locally from an IDE such as Eclipse or IntelliJ one needs to add configuration to the `application-local.properties` and add the VCI plugin dependency JAR to the certify-service project which implements one of `DataProviderPlugin` or `VCIssuancePlugin` interfaces.
5. Get a compatible eSignet setup running configured with the appropriate Authenticator plugin implementation matching the VCI plugin.
    * Configure `mosip.certify.authorization.url` to point to your Authorization service hostname, this could be a working eSignet instance or another AuthZ provider configured with an [Authenticator plugin implementation](https://docs.esignet.io/integration/authenticator), essentially enabling the VC Issuing plugin to do the work.
    * Configure `mosip.certify.domain.url`, `mosip.certify.identifier`, `mosip.certify.authn.issuer-uri`, `mosip.certify.authn.jwk-set-uri`, `mosip.certify.authn.allowed-audiences` appropriately as per the Authorization service and Certify URI.
    * Update the `mosip.certify.key-values` with the well known appropriately, with the correct credential-type, scope and other relevant attributes.
    * Update the well known configuration in `mosip.certify.key-values` to match the Credential type, scope and other fields to match your VerifiableCredential.
    * Appropriately configure the `mosip.certify.authn.allowed-audiences` to allowed audiences such that it matches with the AuthZ token when the Credential issue request is made to Certify.
6. (required if Mobile driving license configured) Onboard issuer key and certificate data into property `mosip.certify.mock.mdoc.issuer-key-cert` using the creation script.
7. Perform Authentication & VC Issuance to see if the Certify & AuthZ stack is working apprpriately. Look out for the Postman collections referred to in the main README.md of this project.
   * Use the **Inji Certify - Pre Auth Code** collection located at `docs/postman-collections/Inji Certify - Pre Auth Code.postman_collection.json` to test the "Credential Offer with Pre Authorization Code Flow".



# Setup Guide: Custom Plugin with Local `inji-certify` 🚀

This guide outlines how to use an existing certify plugin or build a custom plugin.

-----

## 1. Modifying and Building the Plugin

These steps prepare your custom plugin JAR file.

### 1.1. Clone the Repository

Get the source code for the plugins.

```bash
git clone https://github.com/inji/digital-credential-plugins
```

### 1.2. Using an Existing Plugin
Currently, certify supports 2 types of plugins in `DataProvider` mode.

### 1.2.1. Mock CSV Data Provider Plugin
This plugin reads user data from a CSV file.
- **Location:** [MockCSVDataProviderPlugin](https://github.com/inji/digital-credential-plugins/blob/master/mock-certify-plugin/src/main/java/io.mosip.certify.mock.integration/service/MockCSVDataProviderPlugin.java)

### Configurations required:
```properties
# Set Plugin Mode
mosip.certify.plugin-mode=DataProvider

#Set Plugin Class Implementation
mosip.certify.integration.data-provider-plugin=MockCSVDataProviderPlugin

## CSV Plugin specific configurations
# Path to CSV file
# Classpath can be used to load file from resources folder
mosip.certify.mock.data-provider.csv-registry-uri=classpath:farmer-identity-data.csv
# Use the correct URI if the file is hosted.
#mosip.certify.mock.data-provider.csv-registry-uri=https://inji.github.io/inji-config/collab/farmer-identity-data.csv

# Identifier Column in CSV
mosip.certify.mock.data-provider.csv.identifier-column=id

# CSV data columns
mosip.certify.mock.data-provider.csv.data-columns=id,name,age
```

### Use the plugin as runtime-dependency in certify-service pom.xml
```xml 
<dependency>
    <groupId>io.inji.certify</groupId>
    <artifactId>mock-certify-plugin</artifactId>
    <!-- Use the latest version or the version if the existing plugin is modified --> 
    <version>0.6.0</version>
</dependency>
```

### 1.2.2. Postgres Data Provider Plugin
This plugin fetches user data from a PostgreSQL database.
- **Location:** [PostgresDataProviderPlugin](https://github.com/inji/digital-credential-plugins/tree/master/postgres-dataprovider-plugin)

### Configurations required:
```properties
# Set Plugin Mode
mosip.certify.plugin-mode=DataProvider

#Set Plugin Class Implementation
mosip.certify.integration.data-provider-plugin=PostgresDataProviderPlugin

## Postgres Plugin specific configurations
# Define a OpenID scope to DB query map where :id is fetched from the "sub" field of the token.
# sample_vc_ldp is the credential scope
# farmer_data is the table name and farmer_id is the column to be matched with :id
mosip.certify.data-provider-plugin.postgres.scope-query-mapping={\
    'sample_vc_ldp': 'select * from farmer_data where farmer_id=:id'\
  }
```
### Use the plugin as runtime-dependency in certify-service pom.xml
```xml 
<dependency>
    <groupId>io.inji.certify</groupId>
    <artifactId>postgres-dataprovider-plugin</artifactId>
    <!-- Use the latest version or the version if the existing plugin is modified --> 
    <version>0.6.0</version>
</dependency>
```

### 1.2.3 Develop Your Own Plugin

Create a new project or modify an existing project within the cloned repository.

**References:**
- Implement `DataProviderPlugin` or `VCIssuancePlugin` interfaces from [Certify Plugin API](https://github.com/inji/inji-certify/tree/develop/certify-integration-api/src/main/java/io/mosip/certify/api/spi)
- Write your custom logic to fetch data and/or issue VCs.
**Note:** Recommended to use `DataProviderPlugin` for most use cases.


### 1.3. Build the Plugin

Navigate to your project folder inside the `digital-credential-plugins` repository and run the build command. This generates the snapshot JAR in your local Maven repository.

```bash
mvn clean install -Dgpg.skip=true
```

## Run Inji Certify locally with default-setup
1. Add the plugin dependency to `certify-service/pom.xml` as shown above.
2. Run the application using your IDE from the [Certify Service Application](../certify-service/src/main/java/io/mosip/certify/CertifyServiceApplication.java)
3. Use the CredentialConfig endpoints to add a vc type to local certify issuer. Refer to [Credential-Issuer-Configuration.md](./Credential-Issuer-Configuration.md) and [Mosip Stoplight Documentation](https://mosip.stoplight.io/docs/inji-certify/b27d7165a3af7-add-credential-configuration) for more details.
  **Note:** Refer to [Resources](../certify-service/src/main/resources/) folder for sample configuration files for default setup. Use the `/credential-configurations` POST api endpoint for adding the configuration.
4. Update the `didUrl`, `vcTemplate`, `signatureCryptoSuite`, `keyManagerAppId`, `keyManagerRefId`, `signatureAlgo`, `format` and other relevant fields in the Credential Configuration appropriately to match your plugin and VC format.
5. Access the did.json endpoint at `http://localhost:8090/v1/certify/.well-known/did.json` to get the DID document. This did.json document can be hosted in the following ways:
  - Update the `mosip.certify.data-provider-plugin.did-url` to a did url from where did.json can be hosted.
      ```properties
      mosip.certify.data-provider-plugin.did-url=did:web:someuser.github.io:somerepo:somedirectory
      ```
  - (required for VC verification) Certify will automatically generate the DID document for your use case at [this endpoint](http://localhost:8090/v1/certify/.well-known/did.json), please copy the contents of the HTTP response and host it appropriately in the same location.
    - A did with the ID `did:web:someuser.github.io:somerepo:somedirectory` will be accessible at `https://someuser.github.io/somerepo/somedirectory/did.json`, i.e. if GitHub Pages is used to host the file, the contents should go in https://github.com/someuser/somerepo/blob/gh-pages/somedirectory/did.json assuming `gh-pages` is the branch for publishing GitHub Pages as per repository settings.
    - To verify if everything is working you can try to resolve the DID via public DID resolvers such as [Uniresolver](https://dev.uniresolver.io/).
  - Update the `didUrl` field of the `credentialConfig` to have the same value as the above property to verify the VC.

## VC Issuance With Local Setup
1. Use the Postman collection and environment located at [Inji Certify Mock Collection](./postman-collections/inji-certify-with-mock-identity.postman_collection.json) and [Inji Certify Mock Environment](./postman-collections/inji-certify-with-mock-identity.postman_environment.json) to test the VC issuance flow.
2. Locate the `Get Farmer Credential` POST request inside the VCI folder
3. Send the VC request and the response will be farmer credential json.
4. Try verification with [Univerifier](https://univerifier.io)


## Setting up Presentation During Issuance
To setup presentation requirement during issuance, follow the steps below:
1. **Configuration:** Use the following properties in `application-local.properties` to setup presentation requirement during issuance.
```properties
## Use certify as Auth Server
# Use below properties to use certify as authorization server
#mosip.certify.authorization.url=http://localhost:8090
#mosip.certify.authn.issuer-uri=${mosip.certify.authorization.url}
#mosip.certify.authn.jwk-set-uri=${mosip.certify.authorization.url}${server.servlet.path}/.well-known/jwks.json
#mosip.certify.authn.allowed-audiences={ '${mosip.certify.authorization.url}${server.servlet.path}/issuance/credential' }

## Auth Server Configurations
mosip.certify.oauth.issuer=${mosip.certify.authorization.url}
mosip.certify.oauth.token-endpoint=${mosip.certify.authorization.url}${server.servlet.path}/oauth/token
mosip.certify.oauth.jwks-uri=${mosip.certify.authorization.url}${server.servlet.path}/.well-known/jwks.json
mosip.certify.oauth.grant-types-supported=authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code
mosip.certify.oauth.response-types-supported=code
mosip.certify.oauth.code-challenge-methods-supported=S256
mosip.certify.oauth.interactive-authorization-endpoint=${mosip.certify.authorization.url}${server.servlet.path}/oauth/iae
```
2. **Local VP Request Configuration:** `application-local.properties` points `mosip.certify.vp-request.config-file-url` to `vp_request_config-local.json`. This file contains hardcoded `clientId` and `nonce` values that match the sample DCQL VP token used by the Postman collection, so the embedded Inji Verify library's signature / domain / challenge checks pass without regenerating a VP for every run. Deployment configurations should continue to use `vp_request_config.json` (no hardcoded `clientId` / `nonce`).
3. Refer to the collections in [Presentation During Issuance](./postman-collections/Presentation-During-Issuance.postman_collection.json) and the respective env to test the flow.
4. Use `Discovery Endpoints Copy` to get the issuer and oauth metadata endpoints.
5. Use `IAR Request` to get the IAR code.
6. Use the code to get the access token with `OAuth Token Exchange`.
7. Use the access token to request VC issuance with `Get Credential` request inside the `Credential Download` folder.

## Locally setting up CSV Plugin


The above README can be used to setup the [CSV Plugin](https://github.com/inji/digital-credential-plugins/tree/develop/mock-certify-plugin) and it'll help showcase how one can setup a custom authored plugin for local testing.

Pre-requisites:

* a working Authorization service which gives an identifiable information in the end-user's ID in the `sub` field
* pre-populated CSV file configured with the matching identities to be authenticated against
