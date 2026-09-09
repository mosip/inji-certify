# Developer READMEs

- [Local Development](./technical_docs/Local_Development.md)
- [How to decide b/w VCIssuance & DataProviderPlugin while writing your own](./technical_docs/VCIssuance_Vs_DataProvider.md)
- [Adding credential configuration to Inji Certify](./technical_docs/Credential_Issuer_Configuration.md)
- [SD-JWT VC Support](./technical_docs/SD_JWT_Support.md)
- [Data Integrity Proof Support](./technical_docs/Data_Integrity_Proof_Support.md)
- [VC Revocation Support](./technical_docs/VC_Revocation_Support.md)

# Integrator READMEs

# Postman Collections

Ready-to-import collections and environments under [postman_collections/](./postman_collections/), organized into one folder per flow:

## [authorization_code_flow/](./postman_collections/authorization_code_flow/)
Collections that exercise the OAuth authorization code grant, split by which Certify plugin architecture they demonstrate (see [VCIssuance vs DataProvider](./technical_docs/VCIssuance_Vs_DataProvider.md) for the distinction):

- **[data_provider_plugin/](./postman_collections/authorization_code_flow/data_provider_plugin/)** – exercises the **DataProviderPlugin** architecture.
  - `inji-certify-with-mock-identity.postman_collection.json` + `.postman_environment.json` – Bearer credential issuance against the mock identity system (CSV data-provider "farmer" credential).
  - `inji-certify-with-mock-identity-dpop.postman_collection.json` – DPoP-constrained credential issuance (RFC 9449); shares the environment above.
  - `inji-certify-with-mock-mdoc-vci.postman_collection.json` – mock mDoc/mDL VCI collection.
  - [README-mock-identity-dpop.md](./postman_collections/authorization_code_flow/data_provider_plugin/README-mock-identity-dpop.md) – 26-scenario DPoP conformance suite covering the two mock-identity collections above.
- **[vc_issuance_plugin/](./postman_collections/authorization_code_flow/vc_issuance_plugin/)** – exercises the **VCIssuancePlugin** architecture ("Sunbird VCI Plugin Mode"), using Sunbird RC as the sample integration.
  - `inji-certify-with-sunbird-insurance.postman_collection.json` + `.postman_environment.json`

## [pre_authorization_code_flow/](./postman_collections/pre_authorization_code_flow/)
Tests the Credential Offer with Pre-Authorized Code flow.
- `inji-certify-pre-auth-code.postman_collection.json` + `.postman_environment.json`

## [presentation_during_issuance_flow/](./postman_collections/presentation_during_issuance_flow/)
Tests VC issuance gated behind a presentation request (IAR).
- `inji-certify-presentation-during-issuance-vci.postman_collection.json` + `.postman_environment.json`

## [vc_status_list/](./postman_collections/vc_status_list/)
Tests credential status updates and ledger search.
- `inji-certify-credential-status-and-ledger-search.postman_collection.json`

# Changes between release
- [Releases](./technical_docs/Releases.md)