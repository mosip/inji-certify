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

-- Step 1: Drop the new primary key constraint
ALTER TABLE certify.credential_config DROP CONSTRAINT pk_config_id;

-- Step 2: Drop the partial unique index
DROP INDEX IF EXISTS idx_credential_config_vct_unique;

-- Step 3: Drop all the newly added columns
ALTER TABLE certify.credential_config
    DROP COLUMN credential_config_key_id,
    DROP COLUMN config_id,
    DROP COLUMN status,
    DROP COLUMN doctype,
    DROP COLUMN vct,
    DROP COLUMN credential_format,
    DROP COLUMN did_url,
    DROP COLUMN key_manager_app_id,
    DROP COLUMN key_manager_ref_id,
    DROP COLUMN signature_algo,
    DROP COLUMN sd_claim,
    DROP COLUMN display,
    DROP COLUMN display_order,
    DROP COLUMN scope,
    DROP COLUMN cryptographic_binding_methods_supported,
    DROP COLUMN credential_signing_alg_values_supported,
    DROP COLUMN proof_types_supported,
    DROP COLUMN credential_subject,
    DROP COLUMN claims,
    DROP COLUMN plugin_configurations;

-- Step 4: Rename vc_template back to template
ALTER TABLE certify.credential_config RENAME COLUMN vc_template TO template;

-- Step 5: Restore the column types to original specifications
ALTER TABLE certify.credential_config
    ALTER COLUMN context TYPE character varying(1024),
    ALTER COLUMN credential_type TYPE character varying(512),
    ALTER COLUMN template TYPE VARCHAR;

-- Step 6: Add back the original primary key constraint
ALTER TABLE certify.credential_config ADD CONSTRAINT pk_template PRIMARY KEY (context, credential_type);

-- Step 7: Rename the table back to its original name
ALTER TABLE certify.credential_config RENAME TO credential_template;

COMMENT ON TABLE credential_template IS 'Template Data: Contains velocity template for VC';

COMMENT ON COLUMN credential_template.context IS 'VC Context: Context URL list items separated by comma(,)';
COMMENT ON COLUMN credential_template.credential_type IS 'Credential Type: Credential type list items separated by comma(,)';
COMMENT ON COLUMN credential_template.template IS 'Template Content: Velocity Template to generate the VC';
COMMENT ON COLUMN credential_template.cr_dtimes IS 'Date when the template was inserted in table.';
COMMENT ON COLUMN credential_template.upd_dtimes IS 'Date when the template was last updated in table.';