-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : credential_config, credential_template
-- Purpose    : To remove Certify v0.12.0 changes and make DB ready for Certify v0.11.0
--
-- Create By   	: Piyush Shukla
-- Created Date	: March 2025
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

drop table credential_config;

CREATE TABLE credential_template(
	context character varying(1024) NOT NULL,
	credential_type character varying(512) NOT NULL,
	template VARCHAR NOT NULL,
	cr_dtimes timestamp NOT NULL default now(),
	upd_dtimes timestamp,
	CONSTRAINT pk_template PRIMARY KEY (context, credential_type)
);

COMMENT ON TABLE credential_template IS 'Template Data: Contains velocity template for VC';

COMMENT ON COLUMN credential_template.context IS 'VC Context: Context URL list items separated by comma(,)';
COMMENT ON COLUMN credential_template.credential_type IS 'Credential Type: Credential type list items separated by comma(,)';
COMMENT ON COLUMN credential_template.template IS 'Template Content: Velocity Template to generate the VC';
COMMENT ON COLUMN credential_template.cr_dtimes IS 'Date when the template was inserted in table.';
COMMENT ON COLUMN credential_template.upd_dtimes IS 'Date when the template was last updated in table.';