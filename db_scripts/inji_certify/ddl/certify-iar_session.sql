CREATE TABLE IF NOT EXISTS iar_session (
    id SERIAL PRIMARY KEY,
    auth_session VARCHAR(128) NOT NULL UNIQUE,
    transaction_id VARCHAR(64) NOT NULL,
    cr_dtimes TIMESTAMP NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE iar_session IS 'Maps IAR auth_session to transaction_id for later validation.';
CREATE INDEX IF NOT EXISTS idx_iar_session_auth_session ON iar_session(auth_session);