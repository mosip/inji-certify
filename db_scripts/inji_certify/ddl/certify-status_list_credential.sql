-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : status_list_credential
-- Purpose    : status_list_credential to store status list credential
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------
-- Create ENUM type for credential status
CREATE TYPE credential_status_enum AS ENUM ('AVAILABLE', 'FULL');

-- Create status_list_credential table
CREATE TABLE status_list_credential (
    id VARCHAR(255) PRIMARY KEY,          -- The unique ID (URL/DID/URN) extracted from the VC's 'id' field.
    vc_document VARCHAR NOT NULL,           -- Stores the entire Verifiable Credential JSON document.
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