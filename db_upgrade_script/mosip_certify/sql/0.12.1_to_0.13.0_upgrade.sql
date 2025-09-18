-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : rendering_template,credential_template, ca_cert_store
-- Purpose    : To upgrade Certify v0.12.1 changes and make it compatible with v0.13.0
--
-- Create By   	: Piyush Shukla
-- Created Date	: September-2025
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

-- Step 1: Rename issue_date to issuance_date in ledger table.
ALTER TABLE certify.ledger RENAME COLUMN issue_date TO issuance_date;

-- DROP NOT NULL for credential_id in ledger
ALTER TABLE certify.ledger
    ALTER COLUMN credential_id DROP NOT NULL;

-- Update all existing values to UTC (remove time zone info)
UPDATE certify.ledger SET
    issuance_date = issuance_date AT TIME ZONE 'UTC',
    expiration_date = expiration_date AT TIME ZONE 'UTC';

-- Change column types to TIMESTAMP (without time zone)
ALTER TABLE certify.ledger
    ALTER COLUMN issuance_date TYPE TIMESTAMP,
    ALTER COLUMN expiration_date TYPE TIMESTAMP;

-- DROP NOT NULL for credential_id in  credential_status_transaction
DROP INDEX IF EXISTS idx_cst_credential_id;

-- Drop foreign key to ledger table
ALTER TABLE certify.credential_status_transaction
    DROP CONSTRAINT IF EXISTS fk_credential_status_transaction_ledger;

-- Drop foreign key to status_list_credential table
ALTER TABLE certify.credential_status_transaction
    DROP CONSTRAINT IF EXISTS fk_credential_status_transaction_status_list;

ALTER TABLE credential_status_transaction DROP COLUMN credential_id;

-- Step 2: Create shedlock table for distributed locking
CREATE TABLE IF NOT EXISTS shedlock (
  name VARCHAR(64),
  lock_until TIMESTAMP(3) NULL,
  locked_at TIMESTAMP(3) NULL,
  locked_by VARCHAR(255),
  PRIMARY KEY (name)
)
