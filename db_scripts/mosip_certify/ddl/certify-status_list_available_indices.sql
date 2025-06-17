-- Create status_list_available_indices table
CREATE TABLE status_list_available_indices (
    id SERIAL PRIMARY KEY,                         -- Serial primary key
    status_list_credential_id VARCHAR(255) NOT NULL, -- References status_list_credential.id
    list_index BIGINT NOT NULL,                    -- The numerical index within the status list
    is_assigned BOOLEAN NOT NULL DEFAULT FALSE,   -- Flag indicating if this index has been assigned
    cr_dtimes TIMESTAMP NOT NULL DEFAULT NOW(),   -- Creation timestamp
    upd_dtimes TIMESTAMP,                          -- Update timestamp

    -- Foreign key constraint
    CONSTRAINT fk_status_list_credential
        FOREIGN KEY(status_list_credential_id)
        REFERENCES status_list_credential(id)
        ON DELETE CASCADE -- If a status list credential is deleted, its available index entries are also deleted.
        ON UPDATE CASCADE, -- If the ID of a status list credential changes, update it here too.

    -- Unique constraint to ensure each index within a list is represented only once
    CONSTRAINT uq_list_id_and_index
        UNIQUE (status_list_credential_id, list_index)
);

-- Add comments for documentation
COMMENT ON TABLE status_list_available_indices IS 'Helper table to manage and assign available indices from status list credentials.';
COMMENT ON COLUMN status_list_available_indices.id IS 'Serial primary key for the available index entry.';
COMMENT ON COLUMN status_list_available_indices.status_list_credential_id IS 'Identifier of the status list credential this index belongs to (FK to status_list_credential.id).';
COMMENT ON COLUMN status_list_available_indices.list_index IS 'The numerical index (e.g., 0 to N-1) within the specified status list.';
COMMENT ON COLUMN status_list_available_indices.is_assigned IS 'Flag indicating if this specific index has been assigned (TRUE) or is available (FALSE).';
COMMENT ON COLUMN status_list_available_indices.cr_dtimes IS 'Timestamp when this index entry record was created (typically when the parent status list was populated).';
COMMENT ON COLUMN status_list_available_indices.upd_dtimes IS 'Timestamp when this index entry record was last updated (e.g., when is_assigned changed).';

-- Create indexes for status_list_available_indices
-- Partial index specifically for finding available slots
CREATE INDEX IF NOT EXISTS idx_sla_available_indices
    ON status_list_available_indices (status_list_credential_id, is_assigned, list_index)
    WHERE is_assigned = FALSE;

-- Additional indexes for performance
CREATE INDEX IF NOT EXISTS idx_sla_status_list_credential_id ON status_list_available_indices(status_list_credential_id);
CREATE INDEX IF NOT EXISTS idx_sla_is_assigned ON status_list_available_indices(is_assigned);
CREATE INDEX IF NOT EXISTS idx_sla_list_index ON status_list_available_indices(list_index);
CREATE INDEX IF NOT EXISTS idx_sla_cr_dtimes ON status_list_available_indices(cr_dtimes);