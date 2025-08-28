CREATE TABLE IF NOT EXISTS iar_session (
    id SERIAL PRIMARY KEY,
    auth_session VARCHAR(128) NOT NULL UNIQUE,
    transaction_id VARCHAR(64) NOT NULL,
    client_id VARCHAR(128),
    redirect_uri VARCHAR(512),
    code_challenge VARCHAR(128),
    code_challenge_method VARCHAR(10),
    authorization_code VARCHAR(128),
    code_issued_at TIMESTAMP,
    is_code_used BOOLEAN NOT NULL DEFAULT FALSE,
    cr_dtimes TIMESTAMP NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE iar_session IS 'Maps IAR auth_session to transaction_id and stores OAuth flow state for proper validation.';
CREATE INDEX IF NOT EXISTS idx_iar_session_auth_session ON iar_session(auth_session);
CREATE INDEX IF NOT EXISTS idx_iar_session_authorization_code ON iar_session(authorization_code);