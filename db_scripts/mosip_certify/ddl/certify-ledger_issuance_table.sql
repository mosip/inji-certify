-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : ledger_issuance_table
-- Purpose    : Stores status information for all verifiable credentials following Bitstring status list standards
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------
CREATE TABLE certify.ledger_issuance_table(
    id character varying(255) NOT NULL,
    credential_id character varying(255) NOT NULL,
    issuer_id character varying(255) NOT NULL,
    holder_id character varying(1024) NOT NULL,
    type character varying(50) NOT NULL DEFAULT 'BitstringStatusListEntry',
    status_list_index bigint NOT NULL,
    status_list_credential character varying(255) NOT NULL,
    status_purpose character varying(50),
    credential_status character varying(50) NOT NULL DEFAULT 'valid',
    status_size integer DEFAULT 1,
    status_message jsonb,
    status_reference character varying(512),
    issue_date timestamp NOT NULL,
    expiration_date timestamp,
    revocation_timestamp timestamp,
    revocation_reason character varying(255),
    revocation_proof character varying(512),
    credential_subject_hash character varying(512),
    CONSTRAINT pk_credential_status_id PRIMARY KEY (id),
    CONSTRAINT uk_credential_issuer UNIQUE (credential_id, issuer_id)
);

CREATE INDEX idx_ledger_issuance_table_credential_id ON certify.ledger_issuance_table(credential_id);
CREATE INDEX idx_ledger_issuance_table_issuer_id ON certify.ledger_issuance_table(issuer_id);
CREATE INDEX idx_ledger_issuance_table_status ON certify.ledger_issuance_table(credential_status);
CREATE INDEX idx_ledger_issuance_table_purpose ON certify.ledger_issuance_table(status_purpose);

COMMENT ON TABLE certify.ledger_issuance_table IS 'Contains status information for all verifiable credentials following Bitstring status list standards';
COMMENT ON COLUMN certify.ledger_issuance_table.id IS 'Unique identifier for the credential status record';
COMMENT ON COLUMN certify.ledger_issuance_table.credential_id IS 'Identifier of the verifiable credential';
COMMENT ON COLUMN certify.ledger_issuance_table.issuer_id IS 'Identifier of the credential issuer';
COMMENT ON COLUMN certify.ledger_issuance_table.type IS 'Type of status entry, must be BitstringStatusListEntry for Bitstring standard compliance';
COMMENT ON COLUMN certify.ledger_issuance_table.status_list_index IS 'Index position in the BitString status list where this credential status is stored';
COMMENT ON COLUMN certify.ledger_issuance_table.status_list_credential IS 'URL of the BitString status list credential';
COMMENT ON COLUMN certify.ledger_issuance_table.status_purpose IS 'Purpose of the status entry (e.g., revocation, suspension, message, refresh)';
COMMENT ON COLUMN certify.ledger_issuance_table.credential_status IS 'Current status of the credential (e.g., valid, revoked, suspended)';
COMMENT ON COLUMN certify.ledger_issuance_table.status_size IS 'Size of the status entry in bits, defaults to 1 if not specified';
COMMENT ON COLUMN certify.ledger_issuance_table.status_message IS 'JSON array containing possible status messages and their associated values';
COMMENT ON COLUMN certify.ledger_issuance_table.status_reference IS 'URL or array of URLs which dereference to material related to the status';
COMMENT ON COLUMN certify.ledger_issuance_table.issue_date IS 'Date and time when the credential was issued';
COMMENT ON COLUMN certify.ledger_issuance_table.expiration_date IS 'Date and time when the credential will expire (if applicable)';
COMMENT ON COLUMN certify.ledger_issuance_table.revocation_timestamp IS 'Date and time when the credential was revoked (if applicable)';
COMMENT ON COLUMN certify.ledger_issuance_table.revocation_reason IS 'Reason for revocation (if applicable)';
COMMENT ON COLUMN certify.ledger_issuance_table.revocation_proof IS 'Cryptographic proof or hash representing the integrity of the revocation action';
COMMENT ON COLUMN certify.status_list_credential.encoded_list IS 'Multibase-encoded base64url representation of the GZIP-compressed bitstring values';