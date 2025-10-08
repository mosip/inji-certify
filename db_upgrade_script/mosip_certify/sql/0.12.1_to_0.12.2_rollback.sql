-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name :shedlock, credential_status_transaction
-- Purpose    : To remove Certify v0.12.2 changes and make DB ready for Certify v0.12.1
--
-- Create By   	: Piyush Shukla
-- Created Date	: October 2025
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

-- Step 1: Drop shedlock table
DROP TABLE IF EXISTS certify.shedlock;

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