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

-- Remove qr_settings and qr_signature_algo columns from credential_config
ALTER TABLE certify.credential_config
    DROP COLUMN IF EXISTS qr_settings,
    DROP COLUMN IF EXISTS qr_signature_algo;

-- IAR Session Table Rollback Script
-- This script removes the iar_session table and all associated objects

-- Drop indexes first
DROP INDEX IF EXISTS certify.idx_iar_session_authorization_code_used;
DROP INDEX IF EXISTS certify.idx_iar_session_expires_at;
DROP INDEX IF EXISTS certify.idx_iar_session_request_id;
DROP INDEX IF EXISTS certify.idx_iar_session_authorization_code;
DROP INDEX IF EXISTS certify.idx_iar_session_auth_session;
DROP INDEX IF EXISTS certify.idx_iar_session_scope;
DROP INDEX IF EXISTS certify.idx_iar_session_transaction_id;

-- Drop the table
DROP TABLE IF EXISTS certify.iar_session;

