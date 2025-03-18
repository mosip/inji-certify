-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : credential_status
-- Purpose    : Stores status information for all verifiable credentials following Bitstring status list standards
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------
CREATE TABLE credential_status(
    id character varying(255) NOT NULL,
    credential_id character varying(255) NOT NULL,
    issuer_id character varying(255) NOT NULL,
    type character varying(50) NOT NULL DEFAULT 'BitstringStatusListEntry',
    status_list_index bigint NOT NULL,
    status_list_credential character varying(255) NOT NULL,
    status_purpose character varying(50) NOT NULL,
    credential_status character varying(50) NOT NULL DEFAULT 'valid',
    status_size integer DEFAULT 1,
    status_message jsonb,
    status_reference character varying(512),
    issue_date timestamp NOT NULL,
    expiration_date timestamp,
    revocation_timestamp timestamp,
    revocation_reason character varying(255),
    revocation_proof character varying(512),
    cr_by character varying(256) NOT NULL,
    cr_dtimes timestamp NOT NULL,
    upd_by character varying(256),
    upd_dtimes timestamp,
    is_deleted boolean DEFAULT FALSE,
    del_dtimes timestamp,
    CONSTRAINT pk_credential_status_id PRIMARY KEY (id),
    CONSTRAINT uk_credential_issuer UNIQUE (credential_id, issuer_id)
);

CREATE INDEX idx_credential_status_credential_id ON credential_status(credential_id);
CREATE INDEX idx_credential_status_issuer_id ON credential_status(issuer_id);
CREATE INDEX idx_credential_status_status ON credential_status(credential_status);
CREATE INDEX idx_credential_status_purpose ON credential_status(status_purpose);

COMMENT ON TABLE credential_status IS 'Contains status information for all verifiable credentials following Bitstring status list standards';
COMMENT ON COLUMN credential_status.id IS 'Unique identifier for the credential status record';
COMMENT ON COLUMN credential_status.credential_id IS 'Identifier of the verifiable credential';
COMMENT ON COLUMN credential_status.issuer_id IS 'Identifier of the credential issuer';
COMMENT ON COLUMN credential_status.type IS 'Type of status entry, must be BitstringStatusListEntry for Bitstring standard compliance';
COMMENT ON COLUMN credential_status.status_list_index IS 'Index position in the BitString status list where this credential status is stored';
COMMENT ON COLUMN credential_status.status_list_credential IS 'URL of the BitString status list credential';
COMMENT ON COLUMN credential_status.status_purpose IS 'Purpose of the status entry (e.g., revocation, suspension, message, refresh)';
COMMENT ON COLUMN credential_status.credential_status IS 'Current status of the credential (e.g., valid, revoked, suspended)';
COMMENT ON COLUMN credential_status.status_size IS 'Size of the status entry in bits, defaults to 1 if not specified';
COMMENT ON COLUMN credential_status.status_message IS 'JSON array containing possible status messages and their associated values';
COMMENT ON COLUMN credential_status.status_reference IS 'URL or array of URLs which dereference to material related to the status';
COMMENT ON COLUMN credential_status.issue_date IS 'Date and time when the credential was issued';
COMMENT ON COLUMN credential_status.expiration_date IS 'Date and time when the credential will expire (if applicable)';
COMMENT ON COLUMN credential_status.revocation_timestamp IS 'Date and time when the credential was revoked (if applicable)';
COMMENT ON COLUMN credential_status.revocation_reason IS 'Reason for revocation (if applicable)';
COMMENT ON COLUMN credential_status.revocation_proof IS 'Cryptographic proof or hash representing the integrity of the revocation action';
COMMENT ON COLUMN credential_status.cr_by IS 'ID or name of the user who created the record';
COMMENT ON COLUMN credential_status.cr_dtimes IS 'Date and Timestamp when the record is created';
COMMENT ON COLUMN credential_status.upd_by IS 'ID or name of the user who updated the record';
COMMENT ON COLUMN credential_status.upd_dtimes IS 'Date and Timestamp when the record was last updated';
COMMENT ON COLUMN credential_status.is_deleted IS 'Flag to mark whether the record is Soft deleted';
COMMENT ON COLUMN credential_status.del_dtimes IS 'Date and Timestamp when the record is soft deleted';