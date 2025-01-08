# Inji Stack Setup

This guide provides instructions for setting up and running Inji Stack for a custom use-case based on an existing configured foundational ID system.
An example for this could be a use-case where Authentication is performed from a pre-existing registry such as a **National ID** being put to use to deliver services such as **Farmer Identity Card** to eligible farmers or a **Mobile Driving License** to eligible drivers. These examples can be further extended for different usecases and used with different OIDC Compatible clients.

On the more technical side, this demo showcases the two types of plugin an implementor can choose to implement depending upon their usecase & requirements & pre-existing identity system.


# QuickStart: Mock Certify Plugin Setup

Expected time to setup: ~10 minutes

You have two options for the certify plugin which gives Verifiable Credentials of different types

1. Farmer Credential: returns an JSON-LD VC and is implemented using the [CSV Plugin](https://github.com/mosip/digital-credential-plugins/blob/release-0.3.x/mock-certify-plugin/src/main/java/io.mosip.certify.mock.integration/service/MockCSVDataProviderPlugin.java).
2. Mobile Driving License Credential: returns an mDL VC and is implemented using the [mock-mdl Plugin](https://github.com/mosip/digital-credential-plugins/blob/release-0.3.x/mock-certify-plugin/src/main/java/io.mosip.certify.mock.integration/service/MDocMockVCIssuancePlugin.java).


## Prerequisites

- Docker and Docker Compose installed on your system
- Git (to clone the repository)
- Basic understanding of Docker and container operations
- Relevant Postman collections available from [here](../../docs/postman-collections/), please add the `mock` ones and install the [pmlib library](https://joolfe.github.io/postman-util-lib/) as per the steps given under the heading `Postman Collection` to the Postman setup
- Network Connectivity to access the AuthZ Service, in this example MOSIP Collab setup has been used
- (optional, required if Farmer Credential configured) GitHub Pages or similar service required to host a DID/public key

## Directory Structure Setup

Create the following directory structure before proceeding:

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

- Supported versions: 0.3.0 and above
- Download the latest JAR from:
  ```
  https://oss.sonatype.org/content/repositories/snapshots/io/mosip/certify/mock-certify-plugin/0.3.0-SNAPSHOT/
  ```
- Place the downloaded JAR in `loader_path/certify/`

### For Advanced Users: Create Custom Plugin

You can create your own plugin by implementing the following interface and place the resultant jar in `loader_path`:

Reference Implementation: [CSVDataProviderPlugin](https://github.com/mosip/digital-credential-plugins/blob/release-0.3.x/mock-certify-plugin/src/main/java/io.mosip.certify.mock.integration/service/MockCSVDataProviderPlugin.java) or [MDocMockVCIssuancePlugin](https://github.com/mosip/digital-credential-plugins/blob/release-0.3.x/mock-certify-plugin/src/main/java/io.mosip.certify.mock.integration/service/MDocMockVCIssuancePlugin.java).

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

- Create a `certs/` directory inside the docker-compose-injistack directory
- Place your PKCS12 keystore file in the `certs` directory as `oidckeystore.p12`. This is required for the Inji Web application and other applications which rely on Mimoto as a BFF and it can be configured as per these [docs](https://docs.inji.io/inji-wallet/inji-mobile/customization-overview/credential_providers#onboarding-mimoto-as-oidc-client-for-a-new-issuer) after the file is downloaded in the `certs` directory as shown in the directory tree.
- Update `mosip.oidc.p12.password` to the password of the `oidckeystore.p12` file in the Mimoto [Config file](./config/mimoto-default.properties).


## Configuration Setup

- If you chose the Recommended option, you just need to set the `active_profile_env` value of the certify service in [docker-compose.yaml](./docker-compose.yaml) as per use case or else configure your custom plugin and name the files & `active_profile_env` appropriately as follows,


| Use Case                      | active_profile_env    | config file                              | 
|-------------------------------|-----------------------|------------------------------------------|
| Farmer credential   (default) | `default, csvdp-farmer` | ./config/certify-csvdp-farmer.properties |
| Mobile driving license        | `default, mock-mdl`     | ./config/certify-mock-mdl.properties     |


### Recommended

- If you are going ahead with the Farmer usecase, configure the below values in [here](config/certify-csvdp-farmer.properties) to refer to the web location where you'd host the DID.

```properties
mosip.certify.data-provider-plugin.issuer-uri=did:web:vharsh.github.io:DID:static
mosip.certify.data-provider-plugin.issuer-public-key-uri=did:web:vharsh.github.io:DID:static#key-0
```

- (required for Farmer setup) Certify will automatically generate the DID document for your usecase at [this endpoint](http://localhost:8090/v1/certify/issuance/.well-known/did.json), please copy the contents of the HTTP response and host it appropriately in the same location.
    - To verify if everything is working you can try to resolve the DID via public DID resolvers such as [Uniresolver](https://dev.uniresolver.io/).

- (required if Mobile driving license configured) Onboard issuer key and certificate data into property `mosip.certify.mock.mdoc.issuer-key-cert` using the creation script

### Advanced users only:

- Configure the endpoint for the public DID. This will be required if Farmer Credential is configured, for more details you can go through docs to setup a [DID document](../../docs/Hosting-DID-Document.md)  or a [Public key](../../docs/Hosting-Public-Key.md) later, for now just set this to your GitHub Pages or any other hosting service. The below configuration will help in the Verification of VCs.

```properties
mosip.certify.data-provider-plugin.issuer-uri=did:web:vharsh.github.io:DID:harsh
mosip.certify.data-provider-plugin.issuer-public-key-uri=did:web:vharsh.github.io:DID:harsh#key-0
```

**Note**: Refer the relevant config file based on use case to connect to the required environment.


Ensure all configuration files are properly updated in the config directory if you have are making any changes suggested for any Advanced usecase:

- certify-default.properties
- certify-csvdp-farmer.properties
- mimoto-default.properties
- mimoto-issuers-config.json
- mimoto-trusted-verifiers.json
- credential-template.html



## Running the Application

### Start the Services

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

### Accessing the Web Interface

1. Open your browser and navigate to `http://localhost:3001`
2. You can:
    - Download credentials
    - View credential status at a Standards Compliant VC Verfier such as [Inji Verify](https://injiverify.collab.mosip.net).

### Accessing the Credentials via the Postman Interface

1. Open Postman
2. Import the [Mock Collections & Environments](../../docs/postman-collections/) from here, make appropriate changes to the Credential Type and contexts as per your VerifiableCredential and the configured WellKnown.
3. You can
    - Download credentials
    - View credential status
    - Manage your digital identity


## Advanced Configurations

1. To use the Verifiable Credential Data Model 2.0 optional features one can configure them in the Velocity Template present in [this file](./certify_init.sql)as per [this draft spec](https://w3c-ccg.github.io/vc-render-method/). The Render Template has to be routable by all the clients and should be available.


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
