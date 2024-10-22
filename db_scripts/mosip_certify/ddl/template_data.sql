-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : template_data
-- Purpose    : Template Data table
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS template_data(
	context character varying(1024) NOT NULL,
	credential_type character varying(512) NOT NULL,
	template VARCHAR NOT NULL,
	cr_dtimes timestamp NOT NULL default now(),
	upd_dtimes timestamp,
	CONSTRAINT pk_template PRIMARY KEY (context, credential_type)
);

COMMENT ON TABLE template_data IS 'Template Data: Contains velocity template for VC';

COMMENT ON COLUMN svg_template.context IS 'VC Context: Context URL list items separated by comma(,)';
COMMENT ON COLUMN svg_template.credential_type IS 'Credential Type: Credential type list items separated by comma(,)';
COMMENT ON COLUMN svg_template.template IS 'Template Content: Velocity Template to generate the VC';
COMMENT ON COLUMN svg_template.cr_dtimes IS 'Date when the template was inserted in table.';
COMMENT ON COLUMN svg_template.upd_dtimes IS 'Date when the template was last updated in table.';
