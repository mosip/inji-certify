-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : rendering_template,credential_template, ca_cert_store
-- Purpose    : To upgrade Certify v0.11.0 changes and make it compatible with v0.12.0
--
-- Create By   	: Piyush Shukla
-- Created Date	: January-2025
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

-- Step 1: Rename the table
ALTER TABLE certify.credential_template RENAME TO credential_config;

-- Step 2: Add new columns
ALTER TABLE certify.credential_config
    ADD COLUMN credential_config_key_id VARCHAR(255) NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    ADD COLUMN config_id VARCHAR(255) DEFAULT gen_random_uuid(),
    ADD COLUMN status VARCHAR(255) DEFAULT 'active',
    ADD COLUMN doctype VARCHAR,
    ADD COLUMN vct VARCHAR,
    ADD COLUMN credential_format VARCHAR(255) NOT NULL DEFAULT 'default_format', -- Adding a default value for NOT NULL constraint
    ADD COLUMN did_url VARCHAR DEFAULT 'did:web:mosip.github.io:inji-config:default', -- Adding a default value for NOT NULL constraint
    ADD COLUMN key_manager_app_id VARCHAR(36) DEFAULT '', -- Adding a default value for NOT NULL constraint
    ADD COLUMN key_manager_ref_id VARCHAR(128),
    ADD COLUMN signature_algo VARCHAR(36),
    ADD COLUMN sd_claim VARCHAR,
    ADD COLUMN display JSONB NOT NULL DEFAULT '[]'::jsonb, -- Adding a default value for NOT NULL constraint
    ADD COLUMN display_order TEXT[] DEFAULT ARRAY[]::TEXT[], -- Adding a default value for NOT NULL constraint
    ADD COLUMN scope VARCHAR(255) NOT NULL DEFAULT '', -- Adding a default value for NOT NULL constraint
    ADD COLUMN cryptographic_binding_methods_supported TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[], -- Adding a default value for NOT NULL constraint
    ADD COLUMN credential_signing_alg_values_supported TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[], -- Adding a default value for NOT NULL constraint
    ADD COLUMN proof_types_supported JSONB NOT NULL DEFAULT '{}'::jsonb, -- Adding a default value for NOT NULL constraint
    ADD COLUMN credential_subject JSONB DEFAULT '{}'::jsonb,
    ADD COLUMN claims JSONB,
    ADD COLUMN plugin_configurations JSONB;

-- Step 3: Rename the template column to match the new schema
ALTER TABLE certify.credential_config RENAME COLUMN template TO vc_template;

-- Step 4: Alter column sizes to match the new schema
ALTER TABLE certify.credential_config
    ALTER COLUMN context TYPE VARCHAR,
    ALTER COLUMN credential_type TYPE VARCHAR;

-- Step 5: Update the primary key constraint
ALTER TABLE certify.credential_config DROP CONSTRAINT pk_template;
ALTER TABLE certify.credential_config ADD CONSTRAINT pk_config_id PRIMARY KEY (context, credential_type, credential_format);
ALTER TABLE certify.credential_config ALTER COLUMN vc_template DROP NOT NULL;

-- Step 6: Create the unique index on vct
CREATE UNIQUE INDEX idx_credential_config_vct_unique
ON credential_config(vct)
WHERE vct IS NOT NULL;

COMMENT ON TABLE credential_config IS 'Credential Config: Contains details of credential configuration.';

COMMENT ON COLUMN credential_config.config_id IS 'Credential Config ID: Unique id assigned to save and identify configuration.';
COMMENT ON COLUMN credential_config.status IS 'Credential Config Status: Status of the credential configuration.';
COMMENT ON COLUMN credential_config.vc_template IS 'VC Template: Template used for the verifiable credential.';
COMMENT ON COLUMN credential_config.doctype IS 'Doc Type: Doc Type specifically for Mdoc VC.';
COMMENT ON COLUMN credential_config.vct IS 'VCT field: VC Type specifically for SD-JWT VC.';
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

-- Create ENUM type for credential status
CREATE TYPE credential_status_enum AS ENUM ('available', 'full');

-- Create status_list_credential table
CREATE TABLE status_list_credential (
    id VARCHAR(255) PRIMARY KEY,          -- The unique ID (URL/DID/URN) extracted from the VC's 'id' field.
    vc_document bytea NOT NULL,           -- Stores the entire Verifiable Credential JSON document.
    credential_type VARCHAR(100) NOT NULL, -- Type of the status list (e.g., 'StatusList2021Credential')
    status_purpose VARCHAR(100),             -- Intended purpose of this list within the system (e.g., 'revocation', 'suspension', 'general'). NULLABLE.
    capacity BIGINT,                        --- length of status list
    credential_status credential_status_enum, -- Use the created ENUM type here
    cr_dtimes timestamp NOT NULL default now(),
    upd_dtimes timestamp                    -- When this VC record was last updated in the system
);

-- Add comments for documentation
COMMENT ON TABLE status_list_credential IS 'Stores full Status List Verifiable Credentials, including their type and intended purpose within the system.';
COMMENT ON COLUMN status_list_credential.id IS 'Unique identifier (URL/DID/URN) of the Status List VC (extracted from vc_document.id). Primary Key.';
COMMENT ON COLUMN status_list_credential.vc_document IS 'The complete JSON document of the Status List Verifiable Credential.';
COMMENT ON COLUMN status_list_credential.credential_type IS 'The type of the Status List credential, often found in vc_document.type (e.g., StatusList2021Credential).';
COMMENT ON COLUMN status_list_credential.status_purpose IS 'The intended purpose assigned to this entire Status List within the system (e.g., revocation, suspension, general). This may be based on convention or system policy, distinct from the credentialStatus.statusPurpose used by individual credentials.';
COMMENT ON COLUMN status_list_credential.cr_dtimes IS 'Timestamp when this Status List VC was first added/fetched into the local system.';
COMMENT ON COLUMN status_list_credential.upd_dtimes IS 'Timestamp when this Status List VC record was last updated.';

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_slc_status_purpose ON status_list_credential(status_purpose);
CREATE INDEX IF NOT EXISTS idx_slc_credential_type ON status_list_credential(credential_type);
CREATE INDEX IF NOT EXISTS idx_slc_credential_status ON status_list_credential(credential_status);
CREATE INDEX IF NOT EXISTS idx_slc_cr_dtimes ON status_list_credential(cr_dtimes);

CREATE TABLE IF NOT EXISTS credential_status_transaction (
    transaction_log_id SERIAL PRIMARY KEY,        -- Unique ID for this transaction log entry
    credential_id VARCHAR(255) NOT NULL,          -- The ID of the credential this transaction pertains to (should exist in ledger.credential_id)
    status_purpose VARCHAR(100),                  -- The purpose of this status update
    status_value boolean,                         -- The status value (true/false)
    status_list_credential_id VARCHAR(255),       -- The ID of the status list credential involved, if any
    status_list_index BIGINT,                     -- The index on the status list, if any
    cr_dtimes TIMESTAMP NOT NULL DEFAULT NOW(),   -- Creation timestamp
    upd_dtimes TIMESTAMP,                         -- Update timestamp

    -- Foreign key constraint to ledger table
    CONSTRAINT fk_credential_status_transaction_ledger
        FOREIGN KEY(credential_id)
        REFERENCES ledger(credential_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,

    -- Foreign key constraint to status_list_credential table
    CONSTRAINT fk_credential_status_transaction_status_list
        FOREIGN KEY(status_list_credential_id)
        REFERENCES status_list_credential(id)
        ON DELETE SET NULL
        ON UPDATE CASCADE
);

-- Add comments for documentation
COMMENT ON TABLE credential_status_transaction IS 'Transaction log for credential status changes and updates.';
COMMENT ON COLUMN credential_status_transaction.transaction_log_id IS 'Serial primary key for the transaction log entry.';
COMMENT ON COLUMN credential_status_transaction.credential_id IS 'The ID of the credential this transaction pertains to (references ledger.credential_id).';
COMMENT ON COLUMN credential_status_transaction.status_purpose IS 'The purpose of this status update (e.g., revocation, suspension).';
COMMENT ON COLUMN credential_status_transaction.status_value IS 'The status value (true for revoked/suspended, false for active).';
COMMENT ON COLUMN credential_status_transaction.status_list_credential_id IS 'The ID of the status list credential involved, if any.';
COMMENT ON COLUMN credential_status_transaction.status_list_index IS 'The index on the status list, if any.';
COMMENT ON COLUMN credential_status_transaction.cr_dtimes IS 'Timestamp when this transaction was created.';
COMMENT ON COLUMN credential_status_transaction.upd_dtimes IS 'Timestamp when this transaction was last updated.';

-- Create indexes for credential_status_transaction
CREATE INDEX IF NOT EXISTS idx_cst_credential_id ON credential_status_transaction(credential_id);
CREATE INDEX IF NOT EXISTS idx_cst_status_purpose ON credential_status_transaction(status_purpose);
CREATE INDEX IF NOT EXISTS idx_cst_status_list_credential_id ON credential_status_transaction(status_list_credential_id);
CREATE INDEX IF NOT EXISTS idx_cst_status_list_index ON credential_status_transaction(status_list_index);
CREATE INDEX IF NOT EXISTS idx_cst_cr_dtimes ON credential_status_transaction(cr_dtimes);
CREATE INDEX IF NOT EXISTS idx_cst_status_value ON credential_status_transaction(status_value);

CREATE TABLE status_list_available_indices (
    id SERIAL PRIMARY KEY,                         -- Serial primary key
    status_list_credential_id VARCHAR(255) NOT NULL, -- References status_list_credential.id
    list_index BIGINT NOT NULL,                    -- The numerical index within the status list
    is_assigned BOOLEAN NOT NULL DEFAULT FALSE,   -- Flag indicating if this index has been assigned
    cr_dtimes TIMESTAMP NOT NULL DEFAULT NOW(),   -- Creation timestamp
    upd_dtimes TIMESTAMP,                          -- Update timestamp

    -- Foreign key constraint
    CONSTRAINT fk_status_list_credential
        FOREIGN KEY(status_list_credential_id)
        REFERENCES status_list_credential(id)
        ON DELETE CASCADE -- If a status list credential is deleted, its available index entries are also deleted.
        ON UPDATE CASCADE, -- If the ID of a status list credential changes, update it here too.

    -- Unique constraint to ensure each index within a list is represented only once
    CONSTRAINT uq_list_id_and_index
        UNIQUE (status_list_credential_id, list_index)
);

-- Add comments for documentation
COMMENT ON TABLE status_list_available_indices IS 'Helper table to manage and assign available indices from status list credentials.';
COMMENT ON COLUMN status_list_available_indices.id IS 'Serial primary key for the available index entry.';
COMMENT ON COLUMN status_list_available_indices.status_list_credential_id IS 'Identifier of the status list credential this index belongs to (FK to status_list_credential.id).';
COMMENT ON COLUMN status_list_available_indices.list_index IS 'The numerical index (e.g., 0 to N-1) within the specified status list.';
COMMENT ON COLUMN status_list_available_indices.is_assigned IS 'Flag indicating if this specific index has been assigned (TRUE) or is available (FALSE).';
COMMENT ON COLUMN status_list_available_indices.cr_dtimes IS 'Timestamp when this index entry record was created (typically when the parent status list was populated).';
COMMENT ON COLUMN status_list_available_indices.upd_dtimes IS 'Timestamp when this index entry record was last updated (e.g., when is_assigned changed).';

-- Create indexes for status_list_available_indices
-- Partial index specifically for finding available slots
CREATE INDEX IF NOT EXISTS idx_sla_available_indices
    ON status_list_available_indices (status_list_credential_id, is_assigned, list_index)
    WHERE is_assigned = FALSE;

-- Additional indexes for performance
CREATE INDEX IF NOT EXISTS idx_sla_status_list_credential_id ON status_list_available_indices(status_list_credential_id);
CREATE INDEX IF NOT EXISTS idx_sla_is_assigned ON status_list_available_indices(is_assigned);
CREATE INDEX IF NOT EXISTS idx_sla_list_index ON status_list_available_indices(list_index);
CREATE INDEX IF NOT EXISTS idx_sla_cr_dtimes ON status_list_available_indices(cr_dtimes);


CREATE TABLE ledger (
    id SERIAL PRIMARY KEY,                          -- Auto-incrementing serial primary key
    credential_id VARCHAR(255) NOT NULL,            -- Unique ID of the Verifiable Credential WHOSE STATUS IS BEING TRACKED
    issuer_id VARCHAR(255) NOT NULL,                -- Issuer of the TRACKED credential
    issue_date TIMESTAMPTZ NOT NULL,                -- Issuance date of the TRACKED credential
    expiration_date TIMESTAMPTZ,                    -- Expiration date of the TRACKED credential, if any
    credential_type VARCHAR(100) NOT NULL,          -- Type of the TRACKED credential (e.g., 'VerifiableId')
    indexed_attributes JSONB,                       -- Optional searchable attributes from the TRACKED credential
    credential_status_details JSONB NOT NULL DEFAULT '[]'::jsonb,    -- Stores a list of status objects for this credential, defaults to an empty array.
    cr_dtimes TIMESTAMP NOT NULL DEFAULT NOW(),     -- Creation timestamp of this ledger entry for the tracked credential

    -- Constraints
    CONSTRAINT uq_ledger_tracked_credential_id UNIQUE (credential_id), -- Ensure tracked credential_id is unique
    CONSTRAINT ensure_credential_status_details_is_array CHECK (jsonb_typeof(credential_status_details) = 'array') -- Ensure it's always a JSON array
);

-- Add comments for documentation
COMMENT ON TABLE ledger IS 'Stores intrinsic information about tracked Verifiable Credentials and their status history.';
COMMENT ON COLUMN ledger.id IS 'Serial primary key for the ledger table.';
COMMENT ON COLUMN ledger.credential_id IS 'Unique identifier of the Verifiable Credential whose status is being tracked. Must be unique across the table.';
COMMENT ON COLUMN ledger.issuer_id IS 'Identifier of the issuer of the tracked credential.';
COMMENT ON COLUMN ledger.issue_date IS 'Issuance date of the tracked credential.';
COMMENT ON COLUMN ledger.expiration_date IS 'Expiration date of the tracked credential, if applicable.';
COMMENT ON COLUMN ledger.credential_type IS 'The type(s) of the tracked credential (e.g., VerifiableId, ProofOfEnrollment).';
COMMENT ON COLUMN ledger.indexed_attributes IS 'Stores specific attributes extracted from the tracked credential for optimized searching.';
COMMENT ON COLUMN ledger.credential_status_details IS 'An array of status objects, guaranteed to be a JSON array (list). Defaults to an empty list []. Each object can contain: status_purpose, status_value (boolean), status_list_credential_id, status_list_index, cr_dtimes, upd_dtimes.';
COMMENT ON COLUMN ledger.cr_dtimes IS 'Timestamp of when this ledger record for the tracked credential was created.';

-- Create indexes for ledger
CREATE INDEX IF NOT EXISTS idx_ledger_credential_id ON ledger(credential_id);
CREATE INDEX IF NOT EXISTS idx_ledger_issuer_id ON ledger(issuer_id);
CREATE INDEX IF NOT EXISTS idx_ledger_credential_type ON ledger(credential_type);
CREATE INDEX IF NOT EXISTS idx_ledger_issue_date ON ledger(issue_date);
CREATE INDEX IF NOT EXISTS idx_ledger_expiration_date ON ledger(expiration_date);
CREATE INDEX IF NOT EXISTS idx_ledger_cr_dtimes ON ledger(cr_dtimes);
CREATE INDEX IF NOT EXISTS idx_gin_ledger_indexed_attrs ON ledger USING GIN (indexed_attributes);
CREATE INDEX IF NOT EXISTS idx_gin_ledger_status_details ON ledger USING GIN (credential_status_details);

