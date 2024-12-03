# VCIssuance vs DataProvider


Certify has a plugin model to issue VCs so that implementors can extend Inji Certify to issue various VCs and and the plugin can be of two types.

1. VCIssuancePlugin
2. DataProviderPlugin

While they are two types of Issuing Plugins, both types are issuing VCs by connecting to a configured datasource. The two types of Plugins enable Inji Certify to operate differ in where VC Signing happens.

## How to choose to implement either one?

- An integrator can choose to implement VCIssuancePlugin interface if they want to implement the VC Signing by themselves. This gives more power to the VC Plugin authors in choosing to support their own formats, signing algorithms which may or may not be supported by Certify.
- There may be a case, where an integrator might want Certify to deal with fewer aspects of VCIssuance or may not trust Certify with their unsigned data payload, in this case the implementors can choose to implement DataProviderPlugin interface and only implement the business logic required to fetch the data based on the claims object.
- Both plugins can leave some aspects of the configuration to the Certify's configuration provider which can be a bunch of static config files or something such as Spring Config Server.

# Summary

| **Property**          |       VCIssuancePlugin             | DataProviderPlugin |
|-------------------|------------------------------------|--------------------|
| VC Signing        | managed by the plugin itself       | done by Inji Certify itself |
| Credential Creation    | done by the plugin itself     | done by plugin itself |
| Signing key management | can be done by plugin or delegated to keymanager lib | done by Inji Certify end-to-end via keymanager |
| VC Issuance            | done by the plugin completely | data is given by the plugin, VC issuance is done by Inji Certify |

# Doubts?

If you've further questions, do not hesitate to ask a question about the same in [MOSIP Community](cd )
