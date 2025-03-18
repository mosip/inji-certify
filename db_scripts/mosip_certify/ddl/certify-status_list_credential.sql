-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : status_list_credential
-- Purpose : Stores BitString status lists for credential status tracking following the standards
--
-- Modified Date Modified By Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------
CREATE TABLE status_list_credential(
    id character varying(255) NOT NULL,
    issuer_id character varying(255) NOT NULL,
    type character varying(100) NOT NULL DEFAULT 'BitstringStatusListCredential',
    encoded_list text NOT NULL,
    list_size integer NOT NULL,
    status_purpose character varying(50) NOT NULL,
    status_size integer DEFAULT 1,
    status_messages jsonb,
    valid_from timestamp NOT NULL,
    valid_until timestamp,
    ttl bigint,
    created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cr_by character varying(256) NOT NULL,
    cr_dtimes timestamp NOT NULL,
    upd_by character varying(256),
    upd_dtimes timestamp,
    is_deleted boolean DEFAULT FALSE,
    del_dtimes timestamp,
    CONSTRAINT pk_status_list_credential_id PRIMARY KEY (id),
    CONSTRAINT uk_issuer_purpose UNIQUE (issuer_id, status_purpose)
);

CREATE INDEX idx_status_list_issuer ON status_list_credential(issuer_id);
CREATE INDEX idx_status_list_purpose ON status_list_credential(status_purpose);
CREATE INDEX idx_status_list_validity ON status_list_credential(valid_from, valid_until);

COMMENT ON TABLE status_list_credential IS 'Contains BitString status lists for verifying credential status according to W3C BitString Status List standard';
COMMENT ON COLUMN status_list_credential.id IS 'Unique identifier for the status list credential (statusListCredential URL)';
COMMENT ON COLUMN status_list_credential.issuer_id IS 'Identifier of the credential issuer who created the status list';
COMMENT ON COLUMN status_list_credential.type IS 'Type of the credential, must include BitstringStatusListCredential';
COMMENT ON COLUMN status_list_credential.encoded_list IS 'Multibase-encoded base64url representation of the GZIP-compressed bitstring values';
COMMENT ON COLUMN status_list_credential.list_size IS 'Size of the BitString status list (minimum 16KB uncompressed)';
COMMENT ON COLUMN status_list_credential.status_purpose IS 'Purpose of the status list (refresh, revocation, suspension, message)';
COMMENT ON COLUMN status_list_credential.status_size IS 'Size of status entries in bits, defaults to 1 if not specified';
COMMENT ON COLUMN status_list_credential.status_messages IS 'JSON array containing possible status messages for message purpose';
COMMENT ON COLUMN status_list_credential.valid_from IS 'Earliest point in time at which the status list is valid (validFrom)';
COMMENT ON COLUMN status_list_credential.valid_until IS 'Latest point in time at which the status list is valid (validUntil)';
COMMENT ON COLUMN status_list_credential.ttl IS 'Time to live in milliseconds before a refresh should be attempted';
COMMENT ON COLUMN status_list_credential.created_at IS 'Date and time when the status list was created';
COMMENT ON COLUMN status_list_credential.updated_at IS 'Date and time when the status list was last updated';
COMMENT ON COLUMN status_list_credential.cr_by IS 'ID or name of the user who created the record';
COMMENT ON COLUMN status_list_credential.cr_dtimes IS 'Date and Timestamp when the record is created';
COMMENT ON COLUMN status_list_credential.upd_by IS 'ID or name of the user who updated the record';
COMMENT ON COLUMN status_list_credential.upd_dtimes IS 'Date and Timestamp when the record was last updated';
COMMENT ON COLUMN status_list_credential.is_deleted IS 'Flag to mark whether the record is Soft deleted';
COMMENT ON COLUMN status_list_credential.del_dtimes IS 'Date and Timestamp when the record is soft deleted';