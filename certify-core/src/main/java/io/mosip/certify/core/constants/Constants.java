/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.constants;

public class Constants {

    public static final String UTC_DATETIME_PATTERN = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
    public static final String SPACE = " ";
    public static final String APPLICATION_ID = "applicationId";
    public static final String REFERENCE_ID = "referenceId";
    public static final String CLIENT_ID = "client_id";
    public static final String CERTIFY_PARTNER_APP_ID = "CERTIFY_PARTNER";
    public static final String CERTIFY_SERVICE_APP_ID = "CERTIFY_SERVICE";
    public static final String CERTIFY_VC_SIGN_RSA = "CERTIFY_VC_SIGN_RSA";
    public static final String CERTIFY_VC_SIGN_ED25519 = "CERTIFY_VC_SIGN_ED25519";
    public static final String ROOT_KEY = "ROOT";
    public static final String EMPTY_REF_ID = "";
    public static final String ED25519_REF_ID = "ED25519_SIGN";
    public static final String TEMPLATE_NAME = "templateName";
    public static final String DID_URL = "didUrl";
    public static final String RENDERING_TEMPLATE_ID = "renderingTemplateId";
    public static final String CERTIFY_VC_SIGN_EC_K1 = "CERTIFY_VC_SIGN_EC_K1";
    public static final String CERTIFY_VC_SIGN_EC_R1 = "CERTIFY_VC_SIGN_EC_R1";
    public static final String EC_SECP256K1_SIGN = "EC_SECP256K1_SIGN";
    public static final String EC_SECP256R1_SIGN = "EC_SECP256R1_SIGN";
    public static final String ACTIVE = "active";
    public static final String INACTIVE = "inactive";
    public static final String DELIMITER = "::";  // delimiter is ::  its not used by url or within any context of VC name and is distinct
    public  static final String SIGNATURE_CRYPTO_SUITE = "SIGNATURE_CRYPTO_SUITE";
    public  static final String VCTYPE = "vct";
    public  static final String CONFIRMATION = "cnf";
    public  static final String ISSUER = "iss";
    public static final String TYPE = "type";

    // mDoc specific
    public static final String DOCTYPE = "docType";
    public static final String CLAIMS = "claims";
    public static final String DID_JWK_PREFIX = "did:jwk:";
    public static final String NAMESPACES = "nameSpaces";
    public static final String DIGEST_ID = "digestID";
    public static final String VALIDITY_INFO = "validityInfo";
    public static final String ELEMENT_IDENTIFIER = "elementIdentifier";
    public static final String ELEMENT_VALUE = "elementValue";
    public static final String __CBOR_TAG = "__cbor_tag";
    public static final String __CBOR_VALUE = "__cbor_value";
    public static final String SIGNED = "signed";
    //End of mDoc specific

    public static final String _HOLDER_ID = "_holderId";
    public static final String CREDENTIAL_CONFIGURATIONS_SUPPORTED = "credential_configurations_supported";
    public static final String MANDATORY = "mandatory";
    public static final String PRE_AUTH_CODE_PREFIX = "pre_auth_code:";
    public static final String CREDENTIAL_OFFER_PREFIX = "credential_offer:";
    public static final String PRE_AUTHORIZED_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    public static final String AS_METADATA_PREFIX = "as_metadata:";
    // Request attribute used by the access token filter to pass the auth-failure reason to the exception handler.
    public static final String AUTH_ERROR_ATTRIBUTE = "certify.authError";
    // Authorization scheme the caller actually used ("Bearer" or "DPoP"), recorded by
    // AccessTokenValidationFilter so the error response can answer in the same scheme.
    public static final String AUTH_SCHEME_ATTRIBUTE = "certify.authScheme";
    // Request attribute carrying the error code behind an auth failure, so the
    // handler advice can answer with it instead of a generic invalid_token.
    public static final String AUTH_ERROR_CODE_ATTRIBUTE = "certify.authErrorCode";
    // Header carrying the DPoP proof JWT (RFC 9449 section 4.1).
    public static final String DPOP = "DPoP";
    // Authorization schemes a token may be presented with, and the value recorded in
    // AUTH_SCHEME_ATTRIBUTE. RFC 9449 spells the DPoP scheme and the DPoP header
    // identically, so SCHEME_DPOP is derived from DPOP rather than repeating the
    // literal - they remain separate concepts and read as such at the call site.
    public static final String SCHEME_BEARER = "Bearer";
    public static final String SCHEME_DPOP = DPOP;
}
