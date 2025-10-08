-- Add PKCE and redirect URI fields to iar_session table
-- This migration adds the missing fields required for OAuth 2.0 + PKCE compliance

ALTER TABLE iar_session 
ADD COLUMN IF NOT EXISTS redirect_uri VARCHAR(512),
ADD COLUMN IF NOT EXISTS code_challenge VARCHAR(128),
ADD COLUMN IF NOT EXISTS code_challenge_method VARCHAR(10);

-- Add comments for documentation
COMMENT ON COLUMN iar_session.redirect_uri IS 'OAuth 2.0 redirect URI from authorization request - must match token request';
COMMENT ON COLUMN iar_session.code_challenge IS 'PKCE code challenge from authorization request';
COMMENT ON COLUMN iar_session.code_challenge_method IS 'PKCE code challenge method (S256 or plain)';

-- Create index on code_challenge for performance
CREATE INDEX IF NOT EXISTS idx_iar_session_code_challenge ON iar_session(code_challenge);

