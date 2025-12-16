CREATE TABLE IF NOT EXISTS iar_session (
    id SERIAL PRIMARY KEY,
    auth_session VARCHAR(128) NOT NULL UNIQUE,
    transaction_id VARCHAR(64) NOT NULL,
    request_id VARCHAR(64),
    verify_nonce VARCHAR(64),
    expires_at TIMESTAMP,
    client_id VARCHAR(128),
    scope VARCHAR(128),
    authorization_code VARCHAR(128),
    response_uri VARCHAR(512),
    code_challenge VARCHAR(128),
    code_challenge_method VARCHAR(10),
    code_issued_at TIMESTAMP,
    is_code_used BOOLEAN NOT NULL DEFAULT FALSE,
    code_used_at TIMESTAMP,
    cr_dtimes TIMESTAMP NOT NULL DEFAULT NOW(),
    identity VARCHAR(64)
);

-- Column comments
COMMENT ON COLUMN iar_session.id IS 'Primary key, auto-incrementing identifier for the session record';
COMMENT ON COLUMN iar_session.auth_session IS 'Unique session identifier returned to client in IAR response, used to correlate VP presentations';
COMMENT ON COLUMN iar_session.transaction_id IS 'Transaction identifier from verify service, used to track the verification process';
COMMENT ON COLUMN iar_session.request_id IS 'Request identifier for tracking and logging purposes';
COMMENT ON COLUMN iar_session.verify_nonce IS 'Nonce value from verify service for VP request security';
COMMENT ON COLUMN iar_session.expires_at IS 'Session expiration timestamp, after which the session becomes invalid';
COMMENT ON COLUMN iar_session.client_id IS 'OAuth client identifier, optional for public clients';
COMMENT ON COLUMN iar_session.scope IS 'OAuth scope extracted from credential configuration';
COMMENT ON COLUMN iar_session.authorization_code IS 'OAuth authorization code generated for token exchange';
COMMENT ON COLUMN iar_session.response_uri IS 'URI where VP presentation response should be sent';
COMMENT ON COLUMN iar_session.code_challenge IS 'PKCE code challenge for OAuth security';
COMMENT ON COLUMN iar_session.code_challenge_method IS 'PKCE code challenge method (typically S256)';
COMMENT ON COLUMN iar_session.code_issued_at IS 'Timestamp when authorization code was generated';
COMMENT ON COLUMN iar_session.is_code_used IS 'Flag indicating if authorization code has been used for token exchange';
COMMENT ON COLUMN iar_session.code_used_at IS 'Timestamp when authorization code was used for token exchange';
COMMENT ON COLUMN iar_session.cr_dtimes IS 'Record creation timestamp';
COMMENT ON COLUMN iar_session.identity IS 'Stores identity attributes (e.g., uin, vid, uid) dynamically as JSON map';

COMMENT ON TABLE iar_session IS 'Maps IAR auth_session to transaction_id and stores OAuth flow state including verify service details for presentation during issuance flow.';
CREATE INDEX IF NOT EXISTS idx_iar_session_auth_session ON iar_session(auth_session);
CREATE INDEX IF NOT EXISTS idx_iar_session_authorization_code ON iar_session(authorization_code);
CREATE INDEX IF NOT EXISTS idx_iar_session_request_id ON iar_session(request_id);
CREATE INDEX IF NOT EXISTS idx_iar_session_expires_at ON iar_session(expires_at);
CREATE INDEX IF NOT EXISTS idx_iar_session_authorization_code_used ON iar_session(authorization_code, is_code_used) WHERE authorization_code IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_iar_session_scope ON iar_session(scope);