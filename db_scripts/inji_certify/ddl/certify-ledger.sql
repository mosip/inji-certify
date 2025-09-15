-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : ledger
-- Purpose    : Ledger to store status list credential entries
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------
-- Create ledger table (insert only table, data once added will not be updated)
CREATE TABLE ledger (
    id SERIAL PRIMARY KEY,                          -- Auto-incrementing serial primary key
    credential_id VARCHAR(255),            -- Unique ID of the Verifiable Credential WHOSE STATUS IS BEING TRACKED
    issuer_id VARCHAR(255) NOT NULL,                -- Issuer of the TRACKED credential
    issuance_date TIMESTAMP NOT NULL,                -- Issuance date of the TRACKED credential
    expiration_date TIMESTAMP,                    -- Expiration date of the TRACKED credential, if any
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
COMMENT ON COLUMN ledger.issuance_date IS 'Issuance date of the tracked credential.';
COMMENT ON COLUMN ledger.expiration_date IS 'Expiration date of the tracked credential, if applicable.';
COMMENT ON COLUMN ledger.credential_type IS 'The type(s) of the tracked credential (e.g., VerifiableId, ProofOfEnrollment).';
COMMENT ON COLUMN ledger.indexed_attributes IS 'Stores specific attributes extracted from the tracked credential for optimized searching.';
COMMENT ON COLUMN ledger.credential_status_details IS 'An array of status objects, guaranteed to be a JSON array (list). Defaults to an empty list []. Each object can contain: status_purpose, status_value (boolean), status_list_credential_id, status_list_index, cr_dtimes, upd_dtimes.';
COMMENT ON COLUMN ledger.cr_dtimes IS 'Timestamp of when this ledger record for the tracked credential was created.';

-- Create indexes for ledger
CREATE INDEX IF NOT EXISTS idx_ledger_credential_id ON ledger(credential_id);
CREATE INDEX IF NOT EXISTS idx_ledger_issuer_id ON ledger(issuer_id);
CREATE INDEX IF NOT EXISTS idx_ledger_credential_type ON ledger(credential_type);
CREATE INDEX IF NOT EXISTS idx_ledger_issue_date ON ledger(issuance_date);
CREATE INDEX IF NOT EXISTS idx_ledger_expiration_date ON ledger(expiration_date);
CREATE INDEX IF NOT EXISTS idx_ledger_cr_dtimes ON ledger(cr_dtimes);
CREATE INDEX IF NOT EXISTS idx_gin_ledger_indexed_attrs ON ledger USING GIN (indexed_attributes);
CREATE INDEX IF NOT EXISTS idx_gin_ledger_status_details ON ledger USING GIN (credential_status_details);