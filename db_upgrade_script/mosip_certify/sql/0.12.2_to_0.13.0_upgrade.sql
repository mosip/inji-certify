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

-- Change column types to TIMESTAMP (without time zone) while normalizing to UTC
ALTER TABLE certify.ledger
    ALTER COLUMN issuance_date TYPE TIMESTAMP USING (issuance_date AT TIME ZONE 'UTC'),
    ALTER COLUMN expiration_date TYPE TIMESTAMP USING (expiration_date AT TIME ZONE 'UTC');

ALTER TABLE certify.credential_status_transaction
    ALTER COLUMN credential_id DROP NOT NULL;

ALTER TABLE certify.credential_status_transaction
ADD COLUMN processed_dtimes TIMESTAMP NULL;

ALTER TABLE certify.credential_status_transaction
ADD COLUMN is_processed BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN credential_status_transaction.processed_dtimes IS 'Timestamp when this transaction was processed by status list batch job.';
COMMENT ON COLUMN credential_status_transaction.is_processed IS 'Indicates if the transaction has been processed by the status list batch job.';

CREATE INDEX IF NOT EXISTS idx_cst_is_processed_created
ON certify.credential_status_transaction (is_processed, cr_dtimes);

ALTER TABLE certify.credential_status_transaction
DROP COLUMN IF EXISTS upd_dtimes;

DROP INDEX IF EXISTS idx_cst_credential_id;
DROP INDEX IF EXISTS idx_cst_status_purpose;
DROP INDEX IF EXISTS idx_cst_status_list_credential_id;
DROP INDEX IF EXISTS idx_cst_status_list_index;
DROP INDEX IF EXISTS idx_cst_cr_dtimes;
DROP INDEX IF EXISTS idx_cst_status_value;

ALTER TABLE certify.status_list_credential RENAME COLUMN capacity TO capacity_in_kb;

-- Removing status_value from credential_status_details array of ledger table
UPDATE certify.ledger
SET credential_status_details = (
  SELECT COALESCE(
    jsonb_agg(elem - 'status_value'),
    '[]'::jsonb
  )
  FROM jsonb_array_elements(COALESCE(credential_status_details, '[]'::jsonb)) elem
);
