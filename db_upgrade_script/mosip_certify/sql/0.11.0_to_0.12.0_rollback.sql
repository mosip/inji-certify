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
DROP INDEX IF EXISTS idx_credential_config_sd_jwt_vct_unique;
DROP INDEX IF EXISTS idx_credential_config_type_context_unique;
DROP INDEX IF EXISTS idx_credential_config_doctype_unique;

-- Step 3: Drop all the newly added columns
ALTER TABLE certify.credential_config
    DROP COLUMN credential_config_key_id,
    DROP COLUMN config_id,
    DROP COLUMN status,
    DROP COLUMN doctype,
    DROP COLUMN sd_jwt_vct,
    DROP COLUMN credential_format,
    DROP COLUMN did_url,
    DROP COLUMN key_manager_app_id,
    DROP COLUMN key_manager_ref_id,
    DROP COLUMN signature_algo,
    DROP COLUMN signature_crypto_suite,
    DROP COLUMN sd_claim,
    DROP COLUMN display,
    DROP COLUMN display_order,
    DROP COLUMN scope,
    DROP COLUMN cryptographic_binding_methods_supported,
    DROP COLUMN credential_signing_alg_values_supported,
    DROP COLUMN proof_types_supported,
    DROP COLUMN credential_subject,
    DROP COLUMN mso_mdoc_claims,
    DROP COLUMN sd_jwt_claims,
    DROP COLUMN plugin_configurations;
    DROP COLUMN credential_status_purpose;

-- Step 4: Rename vc_template back to template
ALTER TABLE certify.credential_config RENAME COLUMN vc_template TO template;

-- Update existing rows to ensure no NULL values
UPDATE certify.credential_config
SET
    template = CASE WHEN template IS NULL THEN '{}'::text ELSE template END,
    context = CASE WHEN context IS NULL THEN gen_random_uuid()::text ELSE context END,
    credential_type = CASE WHEN credential_type IS NULL THEN gen_random_uuid()::text ELSE credential_type END
WHERE
    template IS NULL OR context IS NULL OR credential_type IS NULL;


-- Make the column NOT NULL
ALTER TABLE certify.credential_config
    ALTER COLUMN template SET NOT NULL,
    ALTER COLUMN context SET NOT NULL,
    ALTER COLUMN credential_type SET NOT NULL;

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


-- Indexes for credential_status_transaction
DROP INDEX IF EXISTS certify.idx_cst_credential_id;
DROP INDEX IF EXISTS certify.idx_cst_status_purpose;
DROP INDEX IF EXISTS certify.idx_cst_status_list_credential_id;
DROP INDEX IF EXISTS certify.idx_cst_status_list_index;
DROP INDEX IF EXISTS certify.idx_cst_cr_dtimes;
DROP INDEX IF EXISTS certify.idx_cst_status_value;

-- Indexes for status_list_available_indices
DROP INDEX IF EXISTS certify.idx_sla_available_indices;
DROP INDEX IF EXISTS certify.idx_sla_status_list_credential_id;
DROP INDEX IF EXISTS certify.idx_sla_is_assigned;
DROP INDEX IF EXISTS certify.idx_sla_list_index;
DROP INDEX IF EXISTS certify.idx_sla_cr_dtimes;

-- Indexes for ledger
DROP INDEX IF EXISTS certify.idx_ledger_credential_id;
DROP INDEX IF EXISTS certify.idx_ledger_issuer_id;
DROP INDEX IF EXISTS certify.idx_ledger_credential_type;
DROP INDEX IF EXISTS certify.idx_ledger_issue_date;
DROP INDEX IF EXISTS certify.idx_ledger_expiration_date;
DROP INDEX IF EXISTS certify.idx_ledger_cr_dtimes;
DROP INDEX IF EXISTS certify.idx_gin_ledger_indexed_attrs;
DROP INDEX IF EXISTS certify.idx_gin_ledger_status_details;

-- Indexes for status_list_credential
DROP INDEX IF EXISTS certify.idx_slc_status_purpose;
DROP INDEX IF EXISTS certify.idx_slc_credential_type;
DROP INDEX IF EXISTS certify.idx_slc_credential_status;
DROP INDEX IF EXISTS certify.idx_slc_cr_dtimes;


-- ========= Step 2: Drop the newly created tables =========
-- The order is important to respect foreign key constraints.
-- We drop tables with foreign keys first, then the tables they reference.

DROP TABLE IF EXISTS certify.credential_status_transaction;
DROP TABLE IF EXISTS certify.status_list_available_indices;
DROP TABLE IF EXISTS certify.ledger;
DROP TABLE IF EXISTS certify.status_list_credential;


-- ========= Step 3: Drop the custom ENUM type =========
-- This can only be done after all tables using the type have been dropped.
DROP TYPE IF EXISTS certify.credential_status_enum;