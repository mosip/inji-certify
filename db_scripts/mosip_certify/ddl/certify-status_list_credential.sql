-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : status_list_credential
-- Purpose : Stores BitString status lists for credential status tracking following the standards
--
-- Modified Date Modified By Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------
CREATE TABLE certify.status_list_credential (
    id CHARACTER VARYING(255) NOT NULL,
    issuer_id CHARACTER VARYING(255) NOT NULL,
    type CHARACTER VARYING(100) NOT NULL DEFAULT 'BitstringStatusListCredential',
    encoded_list TEXT NOT NULL,
    list_size INTEGER NOT NULL,
    status_purpose CHARACTER VARYING(50) NOT NULL,
    status_size INTEGER DEFAULT 1,
    status_messages JSONB,
    valid_from TIMESTAMP NOT NULL,
    valid_until TIMESTAMP,
    ttl BIGINT,
    CONSTRAINT pk_status_list_credential_id PRIMARY KEY (id),
    CONSTRAINT uk_issuer_purpose UNIQUE (issuer_id, status_purpose)
);

CREATE INDEX idx_status_list_issuer ON certify.status_list_credential(issuer_id);
CREATE INDEX idx_status_list_purpose ON certify.status_list_credential(status_purpose);
CREATE INDEX idx_status_list_validity ON certify.status_list_credential(valid_from, valid_until);

COMMENT ON TABLE certify.status_list_credential IS 'Contains BitString status lists for verifying credential status according to W3C BitString Status List standard';
COMMENT ON COLUMN certify.status_list_credential.id IS 'Unique identifier for the status list credential (statusListCredential URL)';
COMMENT ON COLUMN certify.status_list_credential.issuer_id IS 'Identifier of the credential issuer who created the status list';
COMMENT ON COLUMN certify.status_list_credential.type IS 'Type of the credential, must include BitstringStatusListCredential';
COMMENT ON COLUMN certify.status_list_credential.encoded_list IS 'Multibase-encoded base64url representation of the GZIP-compressed bitstring values';
COMMENT ON COLUMN certify.status_list_credential.list_size IS 'Size of the BitString status list (minimum 16KB uncompressed)';
COMMENT ON COLUMN certify.status_list_credential.status_purpose IS 'Purpose of the status list (refresh, revocation, suspension, message)';
COMMENT ON COLUMN certify.status_list_credential.status_size IS 'Size of status entries in bits, defaults to 1 if not specified';
COMMENT ON COLUMN certify.status_list_credential.status_messages IS 'JSON array containing possible status messages for message purpose';
COMMENT ON COLUMN certify.status_list_credential.valid_from IS 'Earliest point in time at which the status list is valid (validFrom)';
COMMENT ON COLUMN certify.status_list_credential.valid_until IS 'Latest point in time at which the status list is valid (validUntil)';
COMMENT ON COLUMN certify.status_list_credential.ttl IS 'Time to live in milliseconds before a refresh should be attempted';