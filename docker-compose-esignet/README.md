## Overview

This is the docker-compose setup to run esignet UI and esignet-service. This is not for production use.

## What is in the docker-compose setup folder?

1. "config" folder holds the esignet properties file.
2. "docker-compose.yml" file with esignet setup with other required services
3. "init.sql" comprises DDL and DMLs required by esignet.
4. "loader_path" this is esignet mount volume from where all the runtime dependencies are loaded to classpath. If any new esignet plugins to be tested
should be placed in this folder and respective plugin configuration should be updated in config/esignet-default.properties.

```Note: Refer https://docs.esignet.io/integration to know how to create custom plugins to integrate.```

## How to run this setup?

1. Start the docker-compose file

> docker-compose up

2. Download the postman script from [here](https://github.com/mosip/esignet/blob/master/docs/postman-collections/esignet-OIDC-flow-with-mock.postman_collection.json)
and its environment from [here](https://github.com/mosip/esignet/blob/master/docs/postman-collections/esignet-OIDC-flow-with-mock.postman_environment.json)

3. Import the downloaded collection and environment into postman.

4. To create an OIDC/OAuth client, run the below request from the postman collection "OIDC Client mgmt" folder
   * Get CSRF token
   * Create OIDC Client

5. To run the OIDC flow, run the below request(same order) from the postman collection "AuthCode flow with OTP login" folder.
   * Get CSRF token
   * Authorize / OAuthdetails request
   * Send OTP
   * Authenticate User
   * Authorization Code
   * Get Tokens
   * Get userInfo

6. To run the Verifiable Credential Issuance flow, run the below request(same order) from the postman collection "VCI" folder.
   * Get CSRF token
   * Authorize / OAuthdetails request
   * Send OTP
   * Authenticate User V2
   * Authorization Code
   * Get Tokens V2
   * Get Credential


## How to Access esignet UI?

To invoke the authorize endpoint of esignet UI to start OIDC/VCI flow, use the below URL:

http://localhost:3000/authorize?nonce=ere973eieljznge2311&state=eree2311&client_id=health-service-client&redirect_uri=https://healthservices.com/callback&scope=openid&response_type=code&acr_values=mosip:idp:acr:generated-code&claims=%7B%22userinfo%22:%7B%22name%22:%7B%22essential%22:false%7D,%22phone_number%22:%7B%22essential%22:true%7D%7D,%22id_token%22:%7B%7D%7D&claims_locales=en&display=page&state=consent&ui_locales=en-IN

```Note: Change the value of client_id, redirect_uri, acr_values and claims as per your requirement in the above URL.```

