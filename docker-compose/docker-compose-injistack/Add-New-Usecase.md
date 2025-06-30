# Adding a new usecase to Docker Compose Injistack
This document outlines the steps to add a new usecase to the Docker Compose setup for Injistack.

# Current Usecases
Current usecases include:

## Farmer Usecase:
1. Config file: [certify-csvdp-farmer.properties](../../docker-compose/docker-compose-injistack/certify-csvdp-farmer.properties)
2. Plugin Used: mock-certify-plugin
3. Plugin mode: `Data Provider`
4. Conditional Property Name: 
   - `mosip.certify.integration.data-provider-plugin` : `MockCSVDataProviderPlugin`

## New Usecase Setup
## Postgres Plugin Usecase setup:
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
   
2. Add the insert scripts for adding the usecase VC types to the `credential_config` table: 
    ```
    INSERT INTO certify.credential_config (
        credential_config_key_id,
        config_id,
        status,
        vc_template,
        doctype,
        sd_jwt_vct,
        context,
        credential_type,
        credential_format,
        did_url,
        key_manager_app_id,
        key_manager_ref_id,
        signature_algo,
        sd_claim,
        display,
        display_order,
        scope,
        cryptographic_binding_methods_supported,
        credential_signing_alg_values_supported,
        proof_types_supported,
        credential_subject,
        claims,
        plugin_configurations,
        cr_dtimes,
        upd_dtimes
     )
     VALUES (
     'FarmerCredential',
     gen_random_uuid()::VARCHAR(255),  -- generating a unique config_id
     'active',  -- assuming an active status
     '',  -- the VC template from the JSON
     NULL,  -- doctype from JSON
     NULL,  -- vct for SD-JWT VC
     '',  -- context as comma-separated string
     '',  -- credential_type as comma-separated string
     '',  -- credential_format
     '',  -- did_url
     'CERTIFY_VC_SIGN_ED25519',  -- key_manager_app_id
     'ED25519_SIGN',  -- key_manager_ref_id (optional)
     'EdDSA',  -- signature_algo (optional)
     NULL,  -- sd_claim (optional)
     ''::JSONB,  -- display
     ARRAY[],  -- display_order
     '',  -- scope
     ARRAY[''],  -- cryptographic_binding_methods_supported
     ARRAY[''],  -- credential_signing_alg_values_supported
     ''::JSONB,  -- proof_types_supported
     ''::JSONB,  -- credential_subject
     NULL,  -- claims (optional)
     NULL,  -- plugin_configurations
     NOW(),  -- cr_dtimes
     NULL  -- upd_dtimes (optional)
     );
   ```
   
## Update mimoto config:
1. Add the new usecase to the `mimoto` config file located at [mimoto-issuers-config.json](../../docker-compose/docker-compose-injistack/config/mimoto-issuers-config.json):
     ```
     {
        "issuers": [
        {
            "credential_issuer": "Farmer",
            "issuer_id": "Farmer",
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
