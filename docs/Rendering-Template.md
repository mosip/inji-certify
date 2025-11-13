# Rendering Template Integration for Inji Certify (OpenID4VCI 2.0 RenderMethod)

This document explains the integration of Credential rendering templates in Inji Certify using [VC Render Specification](https://w3c-ccg.github.io/vc-render-method/).

1. To use the Verifiable Credential Data Model 2.0 optional features one can configure them in the Velocity Template present in [this file](./certify_init.sql)as per [this draft spec](https://w3c-ccg.github.io/vc-render-method/). The Render Template has to be routable by all the clients and should be cached appropriately. The template is not expected to be updated as the consuming clients are expected to verify the integrity with the provided `digestMultibase`. For detailed information please go through the draft spec.

```json
  "renderMethod": [{
    "type": "TemplateRenderMethod",
    "renderSuite": "svg-mustache",
    "template": {
        "id": "https://yourdomain.certify.io/v1/certify/rendering-template/national-id",
        "mediaType": "image/svg+xml",
        "digestMultibase": "zQmAPdhyxzznFCwYxAp2dRerWC85Wg6wFl9G270iEu5h6JqW"
    }
  }]
```

## ⚙️ Configuration
To enable the SVG rendering template feature, add the following property to your `application.properties` or `application.yml` file:

```properties
mosip.certify.data-provider-plugin.rendering-template-id=<TEMPLATE_ID_IN_DB>
```

## Property Details:
 - **Purpose**: References the ID of the rendering template stored in the rendering_template table.
 - **Required**: Optional. If not set, templates must include a hardcoded digestMultibase value in the renderMethod.
 - **Behavior**: When set, enables dynamic evaluation of ${_renderMethodSVGdigest} in Velocity templates, allowing Certify to substitute the digest value from the specified template.
 - **Default**: None (not configured).

# Note: The table where the templates are stored is `rendering_template`. The `<TEMPLATE_ID_IN_DB>` should match the `id` column in that table.

**Data Model:**
- `rendering_template` table: Stores the raw SVG template and its digest, referenced by the `renderMethod` key.
- `credential_config` table: Stores the Velocity template as a base64-encoded `vc_template` column, which processes the credential structure.

## Adding the `renderMethod` key in the Velocity Template
In the Velocity template used for credential issuance, include the `renderMethod` key as shown below. Ensure to replace the `id` and `digestMultibase` values with those corresponding to your template.

```json
    {
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://mosip.github.io/inji-config/contexts/farmer-context.json"
      ],
      "issuer": "${_issuer}",
      "type": [
        "VerifiableCredential",
        "FarmerCredential"
      ],
      "validFrom": "${validFrom}",
      "validUntil": "${validUntil}",
      "credentialSubject": {
        "farmerId": "${farmerId}",
        "idType": "${idType}",
        "phoneNumber": "${phoneNumber}"
      },
      "renderMethod": [{
        "type": "TemplateRenderMethod",
        "renderSuite": "svg-mustache",
        "template": {
            "digestMultibase": "${_renderMethodSVGdigest}",
            "id": "http://localhost:8090/v1/certify/rendering-template/<TEMPLATE_ID_IN_DB>",
            "mediaType": "image/svg+xml"
            }
        }]
    }
```

**IMPORTANT:** ${_renderMethodSVGdigest} is a system variable populated by Certify when mosip.certify.data-provider-plugin.rendering-template-id is configured. If this property is not set, replace with the hardcoded digest of your template. (see https://w3c-ccg.github.io/vc-render-method/ for digest generation)

**Note**: This template is converted into base64 encoded string and then stored as `vcTemplate` column in the `credential_config` table.

```mermaid
sequenceDiagram
    participant User as 👤 User
    participant MobileWallet as 📱 Mobile Wallet
    participant Admin as 👤 Admin

    box "Inji Certify" #LightBlue
        participant CredentialIssuer as 📜 Credential Issuer
        participant RenderingService as 🔧 Rendering Service
        participant Config as ⚙️ application.properties
        participant TemplateStore as 🗄️ Template Store
    end
    
    %% Setup Phase
    Note over User,TemplateStore: ==================== Setup Phase ====================
    Admin->>TemplateStore: Add New Template using sql queris
    TemplateStore-->>Admin: Template ID
    
    Note over Config: SVG Rendering Template Template Configuration
    Admin->>Config: Configure mosip.certify.data-provider-plugin.rendering-template-id
    Config->>RenderingService: Load template mappings
    
    %% Divider between setup and credential flow
    Note over User,TemplateStore: ==================== Credential Flow ====================
    
    User ->> MobileWallet: Request Credential
    MobileWallet->>CredentialIssuer: Request Credential
    CredentialIssuer->>MobileWallet: Issue VC (openid4vci) (v2.0 Data Model)
    
    MobileWallet->>RenderingService: GET Rendering Template
    RenderingService ->> TemplateStore: Get Rendering Template
    TemplateStore ->> RenderingService: Template
    RenderingService ->> MobileWallet: Template
    Note left of RenderingService: Set Headers:<br/>- Content-Type: image/svg+xml<br/>- Cache-Control: max-age=604800<br/>- Vary: Accept-Language
    MobileWallet->>MobileWallet: Render SVG<br/>(Interactive Display)
```

### 🔄 Credential Flow

1. **User Initiation**: Request credential via Mobile Wallet

2. **VC Issuance**:
   - Wallet → Credential Issuer: /credential request
   - Response: Signed VC with renderMethod claim

3. **Template Fetch**:
```http
GET /rendering-template/vaccine_card_v1
```

4. **SVG Rendering**:
   - Wallet processes SVG with VC data binding

## 🖋️ Response Headers

| Header | Value | Purpose |
|--------|-------|---------|
| Content-Type | image/svg+xml | MIME type enforcement |
| Cache-Control | max-age=604800 | CDN/browser caching |

The digest multibase can be hardcoded or if the template has been stored with Certify's DB & `mosip.certify.data-provider-plugin.rendering-template-id` is set to the correct the value `${_renderMethodSVGdigest}` can be used to enable Certify to evaluate it specifying the id of the rendering-template used. However, for optimal performance, it's recommended to not set this key and instead hardcode the `digestMultibase` value in the Velocity template itself.