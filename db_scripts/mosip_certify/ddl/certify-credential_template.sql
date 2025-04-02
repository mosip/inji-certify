-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : credential_template
-- Purpose    : Template Data table
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
--   6/1/2025			Sasi				Enhance to support multiple formats
-- ------------------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS credential_template(
	context character varying(1024) NOT NULL,
	credential_type character varying(512) NOT NULL,
	template VARCHAR NOT NULL,
	credential_format character varying(1024),
	did_url VARCHAR,
	key_manager_app_id character varying(36) NOT NULL,
    key_manager_ref_id character varying(128),
	signature_algo character(2048),
	sd_claim VARCHAR,
	cr_dtimes timestamp NOT NULL default now(),
	upd_dtimes timestamp,
	CONSTRAINT pk_template PRIMARY KEY (context, credential_type, credential_format)
);

COMMENT ON TABLE credential_template IS 'Template Data: Contains velocity template for VC';

COMMENT ON COLUMN credential_template.context IS 'VC Context: Context URL list items separated by comma(,)';
COMMENT ON COLUMN credential_template.credential_type IS 'Credential Type: Credential type list items separated by comma(,)';
COMMENT ON COLUMN credential_template.template IS 'Template Content: Velocity Template to generate the VC';
COMMENT ON COLUMN credential_template.cr_dtimes IS 'Date when the template was inserted in table.';
COMMENT ON COLUMN credential_template.upd_dtimes IS 'Date when the template was last updated in table.';
COMMENT ON COLUMN credential_template.credential_format IS '';
COMMENT ON COLUMN credential_template.did_url IS 'URL for the public key. Should point to the exact key. Supports DID document or public key';
COMMENT ON COLUMN credential_template.key_manager_app_id IS 'AppId of the keymanager';
COMMENT ON COLUMN credential_template.key_manager_ref_id IS 'RefId of the keymanager';
COMMENT ON COLUMN credential_template.signature_algo IS 'This for VC signature or proof algorithm';
COMMENT ON COLUMN credential_template.sd_claim IS 'This is a comma seperated list for selective disclosure';
