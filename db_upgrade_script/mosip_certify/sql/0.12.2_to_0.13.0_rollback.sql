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
ALTER TABLE certify.ledger RENAME COLUMN issuance_date TO issue_date;

-- Update NULL credential_id values with random UUIDs in ledger table
UPDATE certify.ledger
SET credential_id = gen_random_uuid()
WHERE credential_id IS NULL;

-- Now set the column to NOT NULL
ALTER TABLE certify.ledger
    ALTER COLUMN credential_id SET NOT NULL;

-- Change column types back to TIMESTAMPTZ while preserving UTC semantics
ALTER TABLE certify.ledger
    ALTER COLUMN issue_date TYPE TIMESTAMPTZ USING issue_date AT TIME ZONE 'UTC',
    ALTER COLUMN expiration_date TYPE TIMESTAMPTZ USING expiration_date AT TIME ZONE 'UTC';

-- Update NULL credential_id values with random UUIDs
UPDATE certify.credential_status_transaction
SET credential_id = gen_random_uuid()
WHERE credential_id IS NULL;

-- Now set the column to NOT NULL
ALTER TABLE certify.credential_status_transaction
    ALTER COLUMN credential_id SET NOT NULL;

ALTER TABLE certify.credential_status_transaction
DROP COLUMN IF EXISTS processed_dtimes;

ALTER TABLE certify.credential_status_transaction
DROP COLUMN IF EXISTS is_processed;

DROP INDEX IF EXISTS certify.idx_cst_is_processed_created;

CREATE INDEX IF NOT EXISTS idx_cst_cr_dtimes ON certify.credential_status_transaction(cr_dtimes);
CREATE INDEX IF NOT EXISTS idx_cst_status_list_credential_id ON certify.credential_status_transaction(status_list_credential_id);

ALTER TABLE certify.credential_status_transaction
ADD COLUMN IF NOT EXISTS upd_dtimes TIMESTAMP;