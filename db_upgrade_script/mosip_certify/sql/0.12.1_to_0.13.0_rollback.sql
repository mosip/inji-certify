-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : credential_config, credential_template
-- Purpose    : To remove Certify v0.13.0 changes and make DB ready for Certify v0.12.1
--
-- Create By   	: Piyush Shukla
-- Created Date	: September 2025
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

-- Step 1: Rename issuance_date to issue_date in ledger table.
ALTER TABLE ledger RENAME COLUMN issuance_date TO issue_date;

ALTER TABLE certify.ledger
    ALTER COLUMN credential_id SET NOT NULL;

-- Update all existing values to UTC (assume current values are UTC)
UPDATE ledger SET
    issue_date = issue_date AT TIME ZONE 'UTC',
    expiration_date = expiration_date AT TIME ZONE 'UTC';

-- Change column types back to TIMESTAMPTZ
ALTER TABLE ledger
    ALTER COLUMN issue_date TYPE TIMESTAMPTZ,
    ALTER COLUMN expiration_date TYPE TIMESTAMPTZ;

-- Add credential_id column as NOT NULL (no default)
ALTER TABLE credential_status_transaction
    ADD COLUMN credential_id UUID;

-- Update existing rows with random UUIDs
UPDATE credential_status_transaction
    SET credential_id = gen_random_uuid()
    WHERE credential_id IS NULL;

-- Set NOT NULL constraint after populating values
ALTER TABLE credential_status_transaction
    ALTER COLUMN credential_id SET NOT NULL;

-- Recreate the index on credential_id
CREATE INDEX idx_cst_credential_id ON credential_status_transaction (credential_id);