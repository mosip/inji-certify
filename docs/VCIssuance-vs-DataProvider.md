# VCIssuance vs DataProvider Plugin


Certify has a plugin model to issue VCs so that implementors can extend Inji Certify to issue various VCs and and the plugin can be of two types.

1. VCIssuancePlugin
2. DataProviderPlugin

While they are two types of Issuing Plugins, both types are issuing VCs by connecting to a configured datasource. The two types of Plugins enable Inji Certify to operate differ in where VC Signing happens.

## How to choose to implement either one?

- An integrator can choose to implement VCIssuancePlugin interface if they want to implement the VC Signing by themselves. This gives more power and control to the VC Plugin authors in choosing to support their own formats, signing algorithms which may or may not be supported by Certify.
- There may be a case, where an integrator might want Certify to deal with fewer aspects of VCIssuance or have a pre-existing VC Issuance stack and may just want a Certify as a OpenID4VCI proxy, in this case the implementors can choose to implement VCIssuancePlugin interface which is supposed to give out a valid VC on it's own or with an external stack.
- If an integrator doesn't have an existing VCIssuance stack pre-deployed, they can choose to let Certify do all the heavy lifting with a DataProviderPlugin. They can choose to use any of the sample plugins present in [this repo](https://github.com/mosip/digital-credential-plugins/) or choose to implement their own.

# Doubts?

If you've further questions, do not hesitate to ask a question about the same in [MOSIP Community](https://community.mosip.io)
