-- IAR Session Table Rollback Script
-- This script removes the iar_session table and all associated objects

-- Drop indexes first
DROP INDEX IF EXISTS idx_iar_session_authorization_code_used;
DROP INDEX IF EXISTS idx_iar_session_expires_at;
DROP INDEX IF EXISTS idx_iar_session_request_id;
DROP INDEX IF EXISTS idx_iar_session_authorization_code;
DROP INDEX IF EXISTS idx_iar_session_auth_session;

-- Drop the table
DROP TABLE IF EXISTS iar_session;
