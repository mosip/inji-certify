# Local Development of Inji Certify

**Pre-requisites**: Java 21 installed, Postgres DB installed & configured

1. Clone the repo, usually the active development happens on the `develop` branch but one can try out one of the `release-x.y.z` branches as well.
2. Run the DB init scripts present in `db_scripts/mosip_certify` , running `deploy.sh deploy.properties` is a good way to init the DB.
3. Decide on the issuance mode of Certify. Some plugins enable Certify to operate as a Proxy and others enable it to work as an Issuer, configure `mosip.certify.issuer` appropriately as `PluginIssuer` or `CertifyIssuer`.
    * If you don't have another Issuance module such as Sunbird, MOSIP Stack, you may want to set it up with CertifyIssuer and configure `mosip.certify.issuer.vc-sign-algo`, `mosip.certify.issuer.pub.key`, `mosip.certify.issuer.uri` appropriately.
4. Decide on the VCI plugin for use locally and configure it, while running locally from an IDE such as Eclipse or IntelliJ one needs to add configuration to the `application-local.properties` and add the VCI plugin dependency to the pom.xml of Certify Service.
5. Get an eSignet 1.4.1 setup running configured with the appropriate Authenticator plugin implementation matching the VCI plugin.
    * Configure `mosip.certify.authorization.url` to point to your Authorization service, this could be a working eSignet instance or another AuthZ provider configured with an [Authenticator plugin implementation](https://docs.esignet.io/integration/authenticator)
    * Update the well known configuration in `mosip.certify.key-values` to match the Credential type, scope and other fields to match your VerifiableCredential.
    * Appropriately configure the `mosip.certify.authn.allowed-audiences` to allowed audiences such that it matches with the AuthZ token when the Credential issue request is made to Certify.
6. Perform Authentication & VC Issuance to see if the Certify & AuthZ stack is working apprpriately. Look out for the Postman collections referred to in the main README.md of this project.


## Locally setting up CSV Plugin


The above README can be used to setup the [CSV Plugin](https://github.com/mosip/digital-credential-plugins/tree/develop/mock-certify-plugin) and it'll help showcase how one can setup a custom authored plugin for local testing.

Pre-requisites:

* a working Authorization service which gives an identifiable information in the end-user's ID in the `sub` field
* pre-populated CSV file configured with the matching identities to be authenticated against
