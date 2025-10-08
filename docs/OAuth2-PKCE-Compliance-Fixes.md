# OAuth 2.0 + PKCE Compliance Fixes

## Overview
This document outlines the critical compliance issues found in the `/oauth/token` endpoint implementation and the fixes applied to ensure full OAuth 2.0 Authorization Code Flow with PKCE (RFC 6749 + RFC 7636) compliance.

## Issues Found

### 1. **CRITICAL: Missing PKCE Validation** ❌
- **Issue**: The `code_verifier` was accepted but never validated against the stored `code_challenge`
- **Impact**: Major security vulnerability that defeats PKCE protection
- **Fix**: Added comprehensive PKCE validation with S256 hash verification

### 2. **CRITICAL: Missing Redirect URI Validation** ❌
- **Issue**: `redirect_uri` in token request was never validated against the authorization request
- **Impact**: Allows redirect URI attacks
- **Fix**: Added redirect URI matching validation

### 3. **Missing PKCE Fields in Database** ❌
- **Issue**: `IarSession` entity didn't store PKCE and redirect URI data
- **Impact**: Cannot perform PKCE or redirect URI validation
- **Fix**: Added database fields and migration script

## Fixes Applied

### 1. Database Schema Updates

#### Updated IarSession Entity
```java
// Added fields to IarSession.java
@Column(name = "redirect_uri", length = 512)
private String redirectUri;

@Column(name = "code_challenge", length = 128)
private String codeChallenge;

@Column(name = "code_challenge_method", length = 10)
private String codeChallengeMethod;
```

#### Database Migration Script
```sql
-- add_pkce_fields_to_iar_session.sql
ALTER TABLE iar_session 
ADD COLUMN IF NOT EXISTS redirect_uri VARCHAR(512),
ADD COLUMN IF NOT EXISTS code_challenge VARCHAR(128),
ADD COLUMN IF NOT EXISTS code_challenge_method VARCHAR(10);
```

### 2. PKCE Utility Class
Created `PkceUtil.java` with:
- S256 hash validation (SHA-256 + Base64URL encoding)
- Plain text validation
- Code challenge generation
- Comprehensive error handling

### 3. Enhanced Token Request Validation
Updated `validateAuthorizationCode()` method to include:
- **PKCE Validation**: Verifies `code_verifier` against stored `code_challenge`
- **Redirect URI Validation**: Ensures redirect URI matches between requests
- **Proper Error Responses**: Returns RFC 6749 compliant error codes

### 4. Updated Request Validation
Enhanced `OAuthTokenRequestValidator` to require:
- `code_verifier` for PKCE compliance
- Proper field validation for authorization_code grant

### 5. Session Data Storage
Updated `IarServiceImpl` to store:
- PKCE data (`code_challenge`, `code_challenge_method`)
- Redirect URI from authorization request
- All data needed for token request validation

## Compliance Checklist

### ✅ OAuth 2.0 Authorization Code Flow (RFC 6749)
- [x] Handles `grant_type=authorization_code`
- [x] Validates authorization code format and existence
- [x] Prevents code reuse with `isCodeUsed` flag
- [x] Validates code expiration
- [x] Validates redirect URI matches between requests
- [x] Returns proper error responses (`invalid_request`, `invalid_grant`, `unsupported_grant_type`)
- [x] Returns valid token response with `access_token`, `token_type`, `expires_in`, `c_nonce`

### ✅ PKCE (RFC 7636)
- [x] Validates `code_verifier` against stored `code_challenge`
- [x] Supports S256 hash method (SHA-256 + Base64URL)
- [x] Supports plain text method
- [x] Requires `code_verifier` in token request
- [x] Stores PKCE data from authorization request

### ✅ Public Client Support
- [x] `client_id` is optional for public clients
- [x] `client_secret` is not required for public clients
- [x] Supports anonymous public clients (both `client_id` can be null)

### ✅ Security Best Practices
- [x] Authorization codes expire after short time
- [x] Codes cannot be reused
- [x] Proper logging and exception handling
- [x] Input validation and sanitization

## Testing Recommendations

### 1. PKCE Validation Tests
```bash
# Test S256 PKCE validation
curl -X POST /oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=valid_code" \
  -d "redirect_uri=https://client.example.com/callback" \
  -d "code_verifier=invalid_verifier" \
  -d "client_id=test_client"
# Should return: {"error": "invalid_grant", "error_description": "Invalid code verifier"}
```

### 2. Redirect URI Validation Tests
```bash
# Test redirect URI mismatch
curl -X POST /oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=valid_code" \
  -d "redirect_uri=https://attacker.com/callback" \
  -d "code_verifier=valid_verifier" \
  -d "client_id=test_client"
# Should return: {"error": "invalid_grant", "error_description": "Redirect URI mismatch"}
```

### 3. Public Client Tests
```bash
# Test public client without client_id
curl -X POST /oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=valid_code" \
  -d "redirect_uri=https://client.example.com/callback" \
  -d "code_verifier=valid_verifier"
# Should succeed for anonymous public clients
```

## Migration Steps

1. **Run Database Migration**:
   ```bash
   psql -d inji_certify -f db_scripts/inji_certify/ddl/add_pkce_fields_to_iar_session.sql
   ```

2. **Deploy Updated Code**:
   - Deploy the updated service with new entity fields
   - Ensure all PKCE validation is active

3. **Verify Compliance**:
   - Run the test scenarios above
   - Verify PKCE validation is working
   - Verify redirect URI validation is working

## Security Impact

These fixes address **critical security vulnerabilities**:

1. **PKCE Bypass**: Previously, attackers could use authorization codes without the code verifier
2. **Redirect URI Attacks**: Previously, attackers could use valid codes with different redirect URIs
3. **Code Interception**: PKCE now properly protects against authorization code interception

The implementation is now **fully compliant** with OAuth 2.0 Authorization Code Flow with PKCE (RFC 6749 + RFC 7636).

