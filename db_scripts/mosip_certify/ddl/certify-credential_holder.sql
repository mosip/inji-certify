-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : credential_holder
-- Purpose    : Stores encrypted credential holder information
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------
CREATE TABLE certify.credential_holder(
    id character varying(255) NOT NULL,
    credential_id character varying(255) NOT NULL,
    holder_id character varying(255),
    encrypted_holder_name bytea,
    encrypted_holder_email bytea,
    encrypted_holder_address bytea,
    credential_type character varying(255) NOT NULL,
    created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cr_by character varying(256) NOT NULL,
    upd_by character varying(256),
    upd_dtimes timestamp,
    is_deleted boolean DEFAULT FALSE,
    del_dtimes timestamp,
    CONSTRAINT pk_credential_holder_id PRIMARY KEY (id),
    CONSTRAINT uk_credential_id UNIQUE (credential_id)
);

-- Ensure the correct schema usage
CREATE INDEX idx_credential_holder_credential_id ON certify.credential_holder(credential_id);
CREATE INDEX idx_credential_holder_holder_id ON certify.credential_holder(holder_id);

COMMENT ON TABLE certify.credential_holder IS 'Contains securely stored information about credential holders';
COMMENT ON COLUMN certify.credential_holder.id IS 'Unique identifier for the credential holder record';
COMMENT ON COLUMN certify.credential_holder.credential_id IS 'Identifier of the verifiable credential';
COMMENT ON COLUMN certify.credential_holder.holder_id IS 'Identifier of the credential holder';
COMMENT ON COLUMN certify.credential_holder.encrypted_holder_name IS 'Encrypted name of the credential holder';
COMMENT ON COLUMN certify.credential_holder.encrypted_holder_email IS 'Encrypted email address of the credential holder';
COMMENT ON COLUMN certify.credential_holder.encrypted_holder_address IS 'Encrypted address information of the credential holder';
COMMENT ON COLUMN certify.credential_holder.credential_type IS 'Type of the credential (e.g., Certificate, Degree)';
COMMENT ON COLUMN certify.credential_holder.created_at IS 'Date and time when the record was created';
COMMENT ON COLUMN certify.credential_holder.cr_by IS 'ID or name of the user who created the record';
COMMENT ON COLUMN certify.credential_holder.upd_by IS 'ID or name of the user who updated the record';
COMMENT ON COLUMN certify.credential_holder.upd_dtimes IS 'Date and Timestamp when the record was last updated';
COMMENT ON COLUMN certify.credential_holder.is_deleted IS 'Flag to mark whether the record is Soft deleted';
COMMENT ON COLUMN certify.credential_holder.del_dtimes IS 'Date and Timestamp when the record is soft deleted';

-- Add foreign key constraint with proper schema reference
ALTER TABLE certify.credential_holder
ADD CONSTRAINT fk_credential_holder_status
FOREIGN KEY (credential_id)
REFERENCES certify.credential_status(credential_id) ON DELETE CASCADE;
