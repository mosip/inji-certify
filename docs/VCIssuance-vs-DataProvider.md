# VCIssuance vs DataProvider Plugin


Certify has a plugin model to issue VCs so that implementors can extend Inji Certify to issue various VCs and and the plugin can be of two types.

1. VCIssuancePlugin
2. DataProviderPlugin

While they are two types of Issuing Plugins, both types are issuing VCs by connecting to a configured datasource. The two types of Plugins enable Inji Certify to operate differ in where VC Signing happens.

```mermaid
sequenceDiagram
    participant Client as 🌐 Client
    box Inji Certify #E6F3FF
    participant credential_endpoint as 🔗 Credential API
    participant VelocityEngine as ⚙️ Template Engine
    participant VCSigner as 🔏 VC Signer
    participant TemplateDB as 💾 Template Store
    end
    participant VCIssuancePlugin as 🔌 VC Issuance Plugin
    participant DataProviderPlugin as 🔌 Data Provider Plugin
    
    Note over VCIssuancePlugin: External Plugin
    Note over DataProviderPlugin: External Plugin
    
    Client->>credential_endpoint: Request VC Issuance (OIDC4VCI)
    alt Using VCIssuancePlugin
        credential_endpoint->>VCIssuancePlugin: Forward Request
        Note right of VCIssuancePlugin: Internal Process:<br/>1. Get Data<br/>2. Create VC<br/>3. Sign VC
        VCIssuancePlugin-->>credential_endpoint: Return Complete Signed VC
        
    else Using DataProviderPlugin
        credential_endpoint->>DataProviderPlugin: Request Data
        Note right of DataProviderPlugin: Internal Process:<br/>Get Data
        DataProviderPlugin-->>credential_endpoint: Return Raw Data
        
        credential_endpoint->>TemplateDB: Fetch Credential Template
        TemplateDB-->>credential_endpoint: Return Template
        
        credential_endpoint->>VelocityEngine: Process Template with Raw Data
        VelocityEngine-->>credential_endpoint: Return unsigned Credential Data
        
        credential_endpoint->>VCSigner: Sign Credential
        Note right of VCSigner: Sign VC
        VCSigner-->>credential_endpoint: Return Signed VC 
        
        
    end
    credential_endpoint-->>Client: Return Final VC (OIDC4VCI)
```

## How to choose to implement either one?

- An integrator can choose to implement VCIssuancePlugin interface if they want to implement the VC Signing by themselves. This gives more power and control to the VC Plugin authors in choosing to support their own formats, signing algorithms which may or may not be supported by Certify.
- There may be a case, where an integrator might want Certify to deal with fewer aspects of VCIssuance or have a pre-existing VC Issuance stack and may just want a Certify as a OpenID4VCI proxy, in this case the implementors can choose to implement VCIssuancePlugin interface which is supposed to give out a valid VC on it's own or with an external stack.
- If an integrator doesn't have an existing VCIssuance stack pre-deployed, they can choose to let Certify do all the heavy lifting with a DataProviderPlugin. They can choose to use any of the sample plugins present in [this repo](https://github.com/mosip/digital-credential-plugins/) or choose to implement their own.


# Doubts?

If you've further questions, do not hesitate to ask a question about the same in [MOSIP Community](https://community.mosip.io)
