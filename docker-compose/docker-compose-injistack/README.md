# Inji Stack Setup

This guide provides instructions for setting up and running Inji Stack for a custom use-case using an existing foundational ID system. This shows how an institution can enable it's portfolio of deparments to build upon an existing identity to accelarate independent service delivery. In the below example, we help setup some components of **Inji Stack** which uses an Authorization Service of a **National ID** deployed by MOSIP to help other depute institutions setup a use-case specific Credential Delivery for it's citizens by two independent departments one at a time such as _Agriculture_ & _Transport_. This example demonstrates the delivery of profession specific identity cards to it's citizens **Farmer Identity Card** to eligible farmers by the **Agriculture Department** or a **Mobile Driving License** to eligible drivers by the **Transport Department**. These examples can be further extended for different usecases and used with different OIDC Compatible clients.

On the more technical side, this demo showcases the two types of plugin an implementor can choose to implement depending upon their usecase & requirements and can even point to another pre-existing identity system demonstrating it's adaptability to various usecases while being backed by open standards which leads to faster adoption and widespread acceptability.


# QuickStart: Mock Certify Plugin Setup

Expected time to setup: ~10 minutes

You have two options for the certify plugin which gives Verifiable Credentials of different types

1. Farmer Credential: returns an JSON-LD VC and is implemented using the [CSV Plugin](https://github.com/mosip/digital-credential-plugins/blob/release-0.5.x/mock-certify-plugin/src/main/java/io.mosip.certify.mock.integration/service/MockCSVDataProviderPlugin.java).
2. Mobile Driving License Credential: returns an mDL VC and is implemented using the [mock-mdl Plugin](https://github.com/mosip/digital-credential-plugins/blob/release-0.5.x/mock-certify-plugin/src/main/java/io.mosip.certify.mock.integration/service/MDocMockVCIssuancePlugin.java).


## Prerequisites

- Docker and Docker Compose installed on your system
- Git (to clone the repository)
- Basic understanding of Docker and container operations
- Relevant Postman collections available from [here](../../docs/postman-collections/), please add the `mock` ones and install the [pmlib library](https://joolfe.github.io/postman-util-lib/) as per the steps given under the heading `Postman Collection` to the Postman setup
- Network Connectivity to access the AuthZ Service, in this example MOSIP Collab setup has been used
- (optional, required if Farmer Credential configured) GitHub Pages or similar service required to host a DID/public key

## Directory Structure Setup

Create the following directory structure in your local codebase before proceeding inside the `docker-compose` directory:

```
docker-compose-injistack/
├── data/
│   └── CERTIFY_PKCS12/(p12 file generated at runtime)
├── certs/
│   └── oidckeystore.p12 (to be obtained during onboarding of mimoto to esignet)
├── loader_path/
│   └── certify/ (plugin jar to be placed here)
├── config/ (default setup should work as is for csvplugin, any other config changes user can make as per their setup)
│   ├── certify-default.properties
│   ├── certify-csvdp-farmer.properties
│   ├── mimoto-default.properties
│   ├── mimoto-issuers-config.json
│   ├── mimoto-trusted-verifiers.json
│   └── credential-template.html
├── nginx.conf
├── certify_init.sql
└── docker-compose.yml
```



## Choosing a VCI plugin for issuance


### Recommended: Use one of the Existing Mock Plugin

- Supported versions: 0.5.0 and above
- Download the latest JAR from:
  ```
  https://oss.sonatype.org/content/repositories/snapshots/io/mosip/certify/mock-certify-plugin/
  ```
- Place the downloaded JAR in `loader_path/certify/`

### For Advanced Users: Create Custom Plugin

You can create your own plugin by implementing the following interface and place the resultant jar in `loader_path`:

Reference Implementation: [CSVDataProviderPlugin](https://github.com/mosip/digital-credential-plugins/blob/release-0.5.x/mock-certify-plugin/src/main/java/io.mosip.certify.mock.integration/service/MockCSVDataProviderPlugin.java) or [MDocMockVCIssuancePlugin](https://github.com/mosip/digital-credential-plugins/blob/release-0.5.x/mock-certify-plugin/src/main/java/io.mosip.certify.mock.integration/service/MDocMockVCIssuancePlugin.java).

```java
public interface DataProviderPlugin {
    // Implement your custom logic here
}
```

or, if you chose the VCIssuancePlugin implement the below interface. The above two examples

```java
public interface VCIssuancePlugin {
    // Implement your custom logic here
}
```

## Certificate Setup

**Note**: This step is required only if you are using the Inji Web application for your usecase.

- Create a `certs/` directory inside the docker-compose-injistack directory.
- Place your PKCS12 keystore file in the `certs` directory as `oidckeystore.p12`. This is required for the Inji Web application and other applications which rely on Mimoto as a BFF and it can be configured as per these [docs](https://docs.inji.io/inji-wallet/inji-mobile/technical-overview/customization-overview/credential_providers#onboarding-mimoto-as-oidc-client-for-a-new-issuer) after the file is downloaded in the `certs` directory as shown in the directory tree.
- Update `oidc_p12_password` env variable under `mimoto-service` in the [docker-compose.yaml](./docker-compose.yaml) to the password of the `oidckeystore.p12` file.


## Configuration Setup

- If you chose the Recommended option, you just need to set the `active_profile_env` value of the certify service in [docker-compose.yaml](./docker-compose.yaml) as per use case or else configure your custom plugin and name the files & `active_profile_env` appropriately as follows,


| Use Case                      | active_profile_env    | config file                              | 
|-------------------------------|-----------------------|------------------------------------------|
| Farmer credential   (default) | `default, csvdp-farmer` | ./config/certify-csvdp-farmer.properties |
| Mobile driving license        | `default, mock-mdl`     | ./config/certify-mock-mdl.properties     |


### Recommended

- If you are going ahead with the Farmer usecase, configure the below values in [here](config/certify-csvdp-farmer.properties) to refer to the web location where you'd host the DID.

```properties
mosip.certify.data-provider-plugin.did-url=did:web:someuser.github.io:somerepo:somedirectory
```

- (required for Farmer setup) Certify will automatically generate the DID document for your usecase at [this endpoint](http://localhost:8090/v1/certify/.well-known/did.json), please copy the contents of the HTTP response and host it appropriately in the same location.
    - A did with the ID `did:web:someuser.github.io:somerepo:somedirectory` will have be accessible at `https://someuser.github.io/somerepo/somedirectory/did.json`, i.e. if GitHub Pages is used to host the file, the contents should go in https://github.com/someuser/somerepo/blob/gh-pages/somedirectory/did.json assuming `gh-pages` is the branch for publishing GitHub Pages as per repository settings.
    - To verify if everything is working you can try to resolve the DID via public DID resolvers such as [Uniresolver](https://dev.uniresolver.io/).

- (required if Mobile driving license configured) Onboard issuer key and certificate data into property `mosip.certify.mock.mdoc.issuer-key-cert` using the creation script, please read the [plugin README](https://github.com/mosip/digital-credential-plugins/tree/release-0.5.x/mock-certify-plugin) for the same.


## Other configurations

**Note**: Refer the relevant config file based on use case to connect to the required environment.

Ensure all configuration files are properly updated in the config directory if you have are making any changes suggested for any Advanced usecase:

- certify-default.properties
- certify-csvdp-farmer.properties

Following files are optional and can be used to configure the Inji Web application for your usecase, if you are not using web application, you can skip these files:

- mimoto-default.properties
- mimoto-issuers-config.json
- mimoto-trusted-verifiers.json
- credential-template.html



## Running the Application

### Start the Services

**Note** : In case you want to access only certify service, you can modify the docker-compose.yaml to remove the other services and run only the `certify` service.

```bash
docker-compose up -d
```

### Verify Services

Check if all services are running:
```bash
docker-compose ps
```

## Service Endpoints

The following services will be available:

- Database (PostgreSQL): `localhost:5433`
- Certify Service: `localhost:8090`
- Mimoto Service: `localhost:8099`
- Inji Web: `localhost:3001`

## Using the Application

### Recommended: Accessing the Web Interface

1. Open your browser and navigate to `http://localhost:3001`
2. You can:
    - Download credentials
    - View credential status at a Standards Compliant VC Verfier such as [Inji Verify](https://injiverify.collab.mosip.net).
3. As a sample, you can try downloading VC with the UIN `5860356276` or `2154189532`. The OTP for this purpose can be given as `111111` which is the Mock OTP for eSignet Collab Environment. The above sample identities should be present at both the Identity Provider(here, National ID) and at the Local Issuer(here, Agriculture Department or Transport Department).

### Running only certify service - Accessing the Credentials via the Postman Interface

1. Open Postman
2. Import the [Mock Collections & Environments](../../docs/postman-collections/) from here, make appropriate changes to the Credential Type and contexts as per your VerifiableCredential and the configured WellKnown.
3. You can
    - Download credentials
    - View credential status
    - Manage your digital identity

Refer to [API documentation](https://mosip.stoplight.io/docs/inji-certify) for detailed usage instructions and examples.


## Advanced Configurations

1. To use the Verifiable Credential Data Model 2.0 optional features one can configure them in the Velocity Template present in [this file](./certify_init.sql)as per [this draft spec](https://w3c-ccg.github.io/vc-render-method/). The Render Template has to be routable by all the clients and should be cached appropriately. The template is not expected to be updated as the consuming clients are expected to verify the integrity with the provided `digestMultibase`. For detailed information please go through the draft spec.

```json
  "renderMethod": [{
    "id": "https://yourdomain.certify.io/v1/certify/rendering-template/national-id",
    "type": "SvgRenderingTemplate",
    "name": "Portrait Mode",
    "css3MediaQuery": "@media (orientation: portrait)",
    "digestMultibase": "zQmAPdhyxzznFCwYxAp2dRerWC85Wg6wFl9G270iEu5h6JqW"
  }]
```

The digest multibase can be hardcoded or if the template has been stored with Certify's DB & `mosip.certify.data-provider-plugin.rendering-template-id` is set to the correct the value `${_renderMethodSVGdigest}` can be used to enable Certify to evaluate it specifying the id of the rendering-template used. However, for optimal performance, it's recommended to not set this key and instead hardcode the `digestMultibase` value in the Velocity template itself.

2. Deploying Inji Certify over a public URL, _using ngrok to demonstrate this_

- change the value of the `mosipbox_public_url` to point to the public URL in ./docker-compose.yaml where Certify service will be accessible, when using locally with ngrok create an HTTP tunnel for the port `8090`, which is the port for Certify and access the Inji Web at http://localhost:3001, to access Inji Web you may have to create another client with the Authorization service and more configuration should be required at Mimoto side

3. To configure your own Google Auth Credentials:
- Refer to the steps documented in the `mimoto` for the same. [GOOGLE_AUTH_SETUP](https://github.com/mosip/mimoto/blob/master/docker-compose/README.md#how-to-create-google-client-credentials)
- Replace the placeholders under the `mimoto-service` in the `docker-compose.yml` file with the generated credentials:

   ```yaml
       environment:
         - GOOGLE_OAUTH_CLIENT_ID=<your-client-id>
         - GOOGLE_OAUTH_CLIENT_SECRET=<your-client-secret>

## Troubleshooting

### Common Issues and Solutions

1. Container startup issues:
   ```bash
   docker-compose logs [service_name]
   ```

2. Database connection issues:
    - Verify PostgreSQL container is running
    - Check database credentials in configuration

3. Plugin loading issues:
    - Verify plugin JAR is in the correct directory
    - Check plugin version compatibility

4. Postman throws an error `pmlib is not defined`
    - Follow the steps defined in the pre-requsites above.

5. The container images for Certify aren't published for the `linux/arm64` architecture yet, if your container runtime returns an error, you can try to run the engine in an emulated mode. This applies to Apple Silicon Mac users running Docker, they'd have to set `export DOCKER_DEFAULT_PLATFORM=linux/amd64` before doing `docker compose up -d`.

6. Apple users using Colima may have issues with the permission of the `data/` directory.
    - Set the owner, group and the permission mode-bits & the file's group & user ownership correctly so that the `local.p12` file can be created inside the data directory.

7. VC download is failing with Mimoto error logs stating that VC Verification is failing.
    - Check if the DID is updated & resolvable. The Multibase hash changes on each restart, please update it whenever a newer instance of Certify is setup.
    - Check if the hosted DID matches with the [DID endpoint](http://localhost:8090/v1/certify/.well-known/did.json)
    - As of now, Mimoto/Inji Web only supports downloads for Ed25519Signature2020 signed VerifiableCredential due to a limitation of the integrated VC-Verification module.


### Health Checks

Monitor service health:
```bash
docker-compose ps
docker logs [container_name]
```

## Hosting a public key in the form of a DID

1. Extract the certificate from the [Ceritfy Endpoint](http://localhost:8090/v1/certify/system-info/certificate?applicationId=CERTIFY_VC_SIGN_ED25519&referenceId=ED25519_SIGN)
2. Use `openssl x509 -pubkey -noout -in filename.pem`  to convert the certificate to a public key.
3. Convert the public key to a publicKeyMultibase as per the [spec](https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/).

## Stopping the Application
To stop all services:
```bash
docker-compose down
```

To stop and remove all containers and volumes:
```bash
docker-compose down -v
```

## Security Considerations

- Keep your PKCS12 certificate secure
- Regularly update configurations and credentials
- Monitor service logs for security issues


## Additional Resources
- [Inji Documentation](https://docs.inji.io/)
