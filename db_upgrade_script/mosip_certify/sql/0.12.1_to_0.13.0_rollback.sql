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

ALTER TABLE certify.ledger
    ALTER COLUMN credential_id SET NOT NULL;

-- Change column types back to TIMESTAMPTZ while preserving UTC semantics
ALTER TABLE certify.ledger
    ALTER COLUMN issue_date TYPE TIMESTAMPTZ USING issue_date AT TIME ZONE 'UTC',
    ALTER COLUMN expiration_date TYPE TIMESTAMPTZ USING expiration_date AT TIME ZONE 'UTC';

ALTER TABLE certify.credential_status_transaction
    ALTER COLUMN credential_id SET NOT NULL;

-- Recreate foreign key to ledger table
ALTER TABLE certify.credential_status_transaction
    ADD CONSTRAINT fk_credential_status_transaction_ledger
    FOREIGN KEY (credential_id)
    REFERENCES certify.ledger(credential_id)
    ON DELETE CASCADE
    ON UPDATE CASCADE;

-- Recreate foreign key to status_list_credential table
ALTER TABLE certify.credential_status_transaction
    ADD CONSTRAINT fk_credential_status_transaction_status_list
    FOREIGN KEY (status_list_credential_id)
    REFERENCES certify.status_list_credential(id)
    ON DELETE SET NULL
    ON UPDATE CASCADE;

-- Step 2: Drop shedlock table
DROP TABLE IF EXISTS certify.shedlock;