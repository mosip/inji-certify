# How to use Mosip IDA DataProvider Plugin with Inji Certify

This guide will walk you through the steps to set up and use the MOSIP IDA DataProvider Plugin with Inji Certify. 
This plugin allows you to fetch user data through an API and use it for issuing Verifiable Credentials (VCs) through Inji Certify.


## Overview
Certify with plugin docker image `inji/certify-with-plugins:0.14.0` has the MOSIP IDA DataProvider Plugin 
pre-integrated and can be used to run Certify with the plugin without needing to build it locally.

## Pre-requisites

Since this plugin issues MOSIP ID as Verifiable Credential, you must set up the MOSIP platform first. See the [MOSIP documentation](https://docs.mosip.io/) for setup details.
At a high level, the following components of MOSIP platform are required to be set up and configured appropriately to use the plugin:
1. MOSIP IDA (Identity Access Management) - This is the core component that manages identity data and provides APIs to access it.
2. Create a Partner through PMS (Partner Management System).
   * Before creating a partner, create a policy.
   * While creating the policy, define the claims (data fields) to fetch from IDA and include in the VC issued by Certify. For example, to include name and date of birth in the VC, define those claims in the policy.

## Configuration to use the plugin with Docker image

Use the following environment variables to configure the plugin when running the docker image. 
These environment variables are mapped to the properties in `certify-<usecase>.properties` file of Certify.


Following properties are required to be set to use the MOSIP IDA DataProvider Plugin:

* Set plugin mode as [DataProvider](https://github.com/inji/inji-config/blob/release-0.15.x/certify-mosipid-identity.properties#L9)
* Set the plugin class implementation to [IdaDataProviderPluginImpl](https://github.com/inji/inji-config/blob/release-0.15.x/certify-mosipid-identity.properties#L8)
* Set the API endpoint to fetch user data [KYC exchange endpoint config](https://github.com/inji/inji-config/blob/release-0.15.x/certify-mosipid-identity.properties#L18-L20)
  * Kyc exchange API is being used to get raw data from IDA 
    * Certify has to be onboarded as MISP partner to access the API, please reach out to MOSIP team to get this done.
    * Once onboarded, you can get the API endpoint and credentials to access the API from MOSIP team and update the properties accordingly.
    * Reference implementation [IdaDataProviderPluginImpl KYC exchange call](https://github.com/inji/digital-credential-plugins/blob/release-0.6.x/mosip-identity-certify-plugin/src/main/java/io/mosip/certify/mosipid/integration/service/IdaDataProviderPluginImpl.java#L119)
* Set up DID. Either use exposed through certify well-known (/.well-known/did.json) or host outside which is publicly accessible and update the `mosip.certify.data-provider-plugin.did-url` property accordingly. [DID URL config](https://github.com/inji/inji-config/blob/release-0.15.x/certify-mosipid-identity.properties#L22)
* Define claims as policy created during partner onboarding. [Claims mapping config](https://github.com/inji/inji-config/blob/release-0.15.x/certify-mosipid-identity.properties#L76)
* Locale supported as per, [Supported locale config](https://github.com/inji/inji-config/blob/release-0.15.x/certify-mosipid-identity.properties#L78)
* Unique identifier used to issue Verifiable Credential is UIN or VID and is inferred based on format/length using regex or policy rules. [Identifier config](https://github.com/inji/inji-config/blob/release-0.15.x/certify-mosipid-identity.properties#L80-L81)
  * This will be used as config for velocity template to issue VC with the identifier in subject. 
  * Reference Implementation
    * [VelocityEnvConfig](https://github.com/inji/inji-certify/blob/release-0.14.x/certify-service/src/main/java/io/mosip/certify/config/VelocityEnvConfig.java)
    * [CertifyIssuanceServiceImpl](https://github.com/inji/inji-certify/blob/release-0.14.x/certify-service/src/main/java/io/mosip/certify/services/CertifyIssuanceServiceImpl.java#L272-L274)


### Configuration to use this plugin at compile time with local setup

Add below dependency in certify-service pom.xml 

```xml 
<dependency>
    <groupId>io.inji.certify</groupId>
    <artifactId>mosip-identity-certify-plugin</artifactId>
    <version>0.6.0</version>
</dependency>
```
