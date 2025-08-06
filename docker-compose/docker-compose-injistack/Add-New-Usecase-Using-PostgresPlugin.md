## Note: This Document is just a draft. More simplified setu steps will be added as an enhancement.
# Adding a new usecase to Docker Compose Injistack
This document outlines the steps to add a new usecase using the Postgres Data Provider Plugin to the Docker Compose setup for Injistack.

# Current Usecases
Current usecases include:

## Farmer Usecase:
1. Config file: [certify-csvdp-farmer.properties](../../docker-compose/docker-compose-injistack/certify-csvdp-farmer.properties)
2. Plugin Used: mock-certify-plugin
3. Plugin mode: `Data Provider`
4. Conditional Property Name: 
   - `mosip.certify.integration.data-provider-plugin` : `MockCSVDataProviderPlugin`
5. Mounted config file of the current usecase in the `docker-compose.yml` file under the `certify` service under `volumes` section:
   - Example:
     ```
     services:
       certify:
         ...
         volumes:
           - ./config/certify-postgres-landregistry.properties:/home/mosip/config/certify-farmer-csvdp.properties
     ```

## New Usecase Setup
## New usecase setup using Postgres Plugin:
1. Usecase Name: `Land Registry Usecase`
2. VC Types: `RegistrationReceiptCredential`, `LandRegistryCredential`

# Steps to Add a New Usecase
1. Add the property config file for the new usecase `certify-postgres-landregistry.properties` in the [config](../../docker-compose/docker-compose-injistack/config) directory.
2. Plugin to be used: `postgres-dataprovider-plugin`
3. Plugin mode: `Data Provider`
4. Conditional Property Name:
   - `mosip.certify.integration.data-provider-plugin` : `PostgresDataProviderPlugin`
5. Mount the config file of the new usecase by adding it to the `docker-compose.yml` file under the `certify` service under `volumes` section:
   - Example:
     ```
     services:
       certify:
         ...
         volumes:
           - ./config/certify-postgres-landregistry.properties:/home/mosip/config/certify-postgres-landregistry.properties
     ```
   
6. Update the `active_profile_env` to use the postgres-landregistry usecase by updating the following line to the `docker-compose.yml` file under the `certify` service under `environment` section:
   ```
   environment:
     - active_profile_env=default, certify-postgres-landregistry
   ```
     

# Add the scripts to create tables and insert data for the usecase specific tables.
1. In the [certify_init.sql](../../docker-compose/docker-compose-injistack/certify_init.sql) file, add the SQL scripts to create the necessary tables and insert data for the new usecase.
   ```
        CREATE TABLE CERTIFY.registration_receipt_data (
        ...
        );
   
       CREATE TABLE CERTIFY.statement_data (
        ...
        );
   
        INSERT INTO CERTIFY.registration_receipt_data 
        (...) 
        VALUES 
        (...);
   
        INSERT INTO CERTIFY.statement_data 
        (...) 
        VALUES 
        (...);
    ```

2. The id or primary key field for the above insert statements should be a valid UIN available in the mock-identity-system if using esignet as the auth provider.
   
2. Use the Credential-Config APIs to add new VC type to the credential_config table
    - Use the `POST /v1/credential-configurations` API to add the new VC type.
      ```
      "/credential-configurations": {
      "post": {
        "tags": [
          "credential-config-controller"
        ],
        "operationId": "addCredentialConfiguration",
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/CredentialConfigurationDTO"
              }
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "OK",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/CredentialConfigResponse"
                }
              }
            }
          }
        }
      }
      ```

3. Request Structure: CredentialConfigurationDTO
   ```
   {
    "credentialConfigKeyId": "RegistrationReceiptCredential",
    "vcTemplate": "",
    "keyManagerAppId": "CERTIFY_VC_SIGN_ED25519",
    "keyManagerRefId": "ED25519_SIGN",
    "signatureAlgo": "EdDSA",
    "context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://mosip.github.io/inji-config/contexts/landregistry-registration-receipt-context.json"
    ],
    "credentialType": [
        "VerifiableCredential",
        "RegistrationReceiptCredential"
    ],
    "credentialFormat": "ldp_vc",
    "didUrl": "did:web:mosip.github.io:inji-config:dev-int-inji:landregistry-ed25519#key-0",
    "display": [{
        "name": "REGISTRATION RECEIPT OF THE RURAL PROPERTY IN CAR",
        "locale": "en",
        "logo": {
        "url": "https://mosip.github.io/inji-config/logos/agro-vertias-logo.png",
        "alt_text": "Registration Receipt Credential logo"
        },
        "background_image": { "uri": "https://mosip.github.io/inji-config/logos/agro-vertias-logo.png" },
        "background_color": "#ebfaff",
        "text_color": "#000000"
    }],
    "order": ["NumberOfCAR","RegistrationDate","RuralPropertyName","Municipality","Latitude","Longitude","TotalArea","FiscalModules","ProtocolCode","CPF","HolderName","TotalDeclaredArea","AdministrativeEasementArea","NetArea","ConsolidatedArea","NativeVegetationRemnant","LegalReserveArea","PermanentPreservationArea","RestrictedUseArea"],
    "scope": "land_registry_vc_ldp",
    "credentialSubject": {
        "NumberOfCAR": {
            "display": [
                {
                "name": "CAR Registration Number",
                "locale": "en"
                }
            ]
        },
        "RegistrationDate": {
            "display": [
                {
                "name": "Registration Date",
                "locale": "en"
                }
            ]
        }
    }
   }
   ```
   
4. Response Structure: CredentialConfigResponse
   ```
   {
    "configId": "<UUID>",
    "status": "active"
   }
   ```

5. Test the well-known endpoint to ensure the new VC type is available:
   - Access the well-known endpoint: `http://localhost:8090/.well-known/credential-configurations`
   - Verify that the new VC type is listed in the response.
    
   
## Update mimoto config:
1. Add the new usecase to the `mimoto` config file located at [mimoto-issuers-config.json](../../docker-compose/docker-compose-injistack/config/mimoto-issuers-config.json):
     ```
     {
        "issuers": [
        {
            "credential_issuer": "Landregistry",
            "issuer_id": "Landregisrty",
            "protocol": "OpenId4VCI",
            "display": [
            {
            "name": "Landregistry Department",
            "logo": {
            "url": "https://mosip.github.io/inji-config/logos/agro-vertias-logo.png",
            "alt_text": "landregistry-logo"
            },
            "title": "Landregistry Department",
            "description": "Download Landregistry Credentials",
            "language": "en"
            }
            ],
            "client_id": "wallet-demo",
            "redirect_uri": "io.mosip.residentapp.inji://oauthredirect",
            "token_endpoint": "http://localhost:8099/v1/mimoto/get-token/Landregistry",
            "authorization_audience": "https://esignet-mock.collab.mosip.net/v1/esignet/oauth/v2/token",
            "proxy_token_endpoint": "https://esignet-mock.collab.mosip.net/v1/esignet/oauth/v2/token",
            "client_alias": "wallet-demo-client",
            "qr_code_type": "EmbeddedVC",
            "enabled": "true",
            "wellknown_endpoint": "http://certify-nginx:80/.well-known/openid-credential-issuer"
        }]
    }
     ```
