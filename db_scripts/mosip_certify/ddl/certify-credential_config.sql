-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : credential_config
-- Purpose    : Credential Configuration Table
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

CREATE TABLE credential_config (
    config_id VARCHAR(255),
    status VARCHAR(255),
    vc_template VARCHAR,
    doctype VARCHAR,
    context VARCHAR NOT NULL,
    credential_type VARCHAR NOT NULL,
    credential_format VARCHAR(255) NOT NULL,
    did_url VARCHAR NOT NULL,
    key_manager_app_id VARCHAR(36) NOT NULL,
    key_manager_ref_id VARCHAR(128),
    signature_algo VARCHAR(36),
    sd_claim VARCHAR,
    display JSONB NOT NULL,
    display_order TEXT[] NOT NULL,
    scope VARCHAR(255) NOT NULL,
    cryptographic_binding_methods_supported TEXT[] NOT NULL,
    credential_signing_alg_values_supported TEXT[] NOT NULL,
    proof_types_supported JSONB NOT NULL,
	credential_subject JSONB,
	claims JSONB,
    plugin_configurations JSONB,
	cr_dtimes TIMESTAMP NOT NULL,
    upd_dtimes TIMESTAMP,
    CONSTRAINT pk_config_id PRIMARY KEY (context, credential_type, credential_format)
);

COMMENT ON TABLE credential_config IS 'Credential Config: Contains details of credential configuration.';

COMMENT ON COLUMN credential_config.id IS 'Credential Config ID: Unique id assigned to save and identify configuration.';
COMMENT ON COLUMN credential_config.status IS 'Credential Config Status: Status of the credential configuration.';
COMMENT ON COLUMN credential_config.vc_template IS 'VC Template: Template used for the verifiable credential.';
COMMENT ON COLUMN credential_config.doctype IS 'Doc Type: Doc Type specifically for Mdoc VC.';
COMMENT ON COLUMN credential_config.context IS 'Context: Array of context URIs for the credential.';
COMMENT ON COLUMN credential_config.credential_type IS 'Credential Type: Array of credential types supported.';
COMMENT ON COLUMN credential_config.credential_format IS 'Credential Format: Format of the credential (e.g., JWT, JSON-LD).';
COMMENT ON COLUMN credential_config.did_url IS 'DID URL: Decentralized Identifier URL for the issuer.';
COMMENT ON COLUMN credential_config.key_manager_app_id IS 'Key Manager App Id: AppId of the keymanager';
COMMENT ON COLUMN credential_config.key_manager_ref_id IS 'Key Manager Reference Id: RefId of the keymanager';
COMMENT ON COLUMN credential_config.signature_algo IS 'Signature Algorithm: This is for VC signature or proof algorithm';
COMMENT ON COLUMN credential_config.sd_claim IS 'SD Claim: This is a comma separated list for selective disclosure';
COMMENT ON COLUMN credential_config.display IS 'Display: Credential Display object';
COMMENT ON COLUMN credential_config.display_order IS 'Display Order: Array defining the order of display elements.';
COMMENT ON COLUMN credential_config.scope IS 'Scope: Authorization scope for the credential.';
COMMENT ON COLUMN credential_config.cryptographic_binding_methods_supported IS 'Cryptographic Binding Methods: Array of supported binding methods.';
COMMENT ON COLUMN credential_config.credential_signing_alg_values_supported IS 'Credential Signing Algorithms: Array of supported signing algorithms.';
COMMENT ON COLUMN credential_config.proof_types_supported IS 'Proof Types: JSON object containing supported proof types and their configurations.';
COMMENT ON COLUMN credential_config.credential_subject IS 'Credential Subject: JSON object containing subject attributes schema.';
COMMENT ON COLUMN credential_config.claims IS 'Claims: JSON object containing subject attributes schema specifically for Mdoc VC.';
COMMENT ON COLUMN credential_config.plugin_configurations IS 'Plugin Configurations: Array of JSON objects for plugin configurations.';
COMMENT ON COLUMN credential_config.cr_dtimes IS 'Created DateTime: Date and time when the config was inserted in table.';
COMMENT ON COLUMN credential_config.upd_dtimes IS 'Updated DateTime: Date and time when the config was last updated in table.';
