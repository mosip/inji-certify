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

    // NOTE: This is how the nonce is set in the accessToken from the AuthZ server, in the proofJwt this is set as "nonce"
    // ref: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2.1.1 (draft-15 reference)
    public static final String C_NONCE = "c_nonce";
    public static final String C_NONCE_EXPIRES_IN = "c_nonce_expires_in";
    public static final String CLIENT_ID = "client_id";
    public static final String CERTIFY_PARTNER_APP_ID = "CERTIFY_PARTNER";
    public static final String CERTIFY_SERVICE_APP_ID = "CERTIFY_SERVICE";
    public static final String CERTIFY_VC_SIGN_RSA = "CERTIFY_VC_SIGN_RSA";
    public static final String CERTIFY_VC_SIGN_ED25519 = "CERTIFY_VC_SIGN_ED25519";
    public static final String ROOT_KEY = "ROOT";
    public static final String EMPTY_REF_ID = "";
    public static final String ED25519_REF_ID = "ED25519_SIGN";
    public static final String TEMPLATE_NAME = "templateName";
    public static final String ISSUER_URI = "issuerURI";
    public static final String RENDERING_TEMPLATE_ID = "renderingTemplateId";
    public static final String CERTIFY_VC_SIGN_EC_K1 = "CERTIFY_VC_SIGN_EC_K1";
    public static final String CERTIFY_VC_SIGN_EC_R1 = "CERTIFY_VC_SIGN_EC_R1";
    public static final String EC_SECP256K1_SIGN = "EC_SECP256K1_SIGN";
    public static final String EC_SECP256R1_SIGN = "EC_SECP256R1_SIGN";
    public static final String ACTIVE = "active";
    public static final String INACTIVE = "inactive";
    public static final String DELIMITER = "::";  // delimiter is ::  its not used by url or within any context of VC name and is distinct
}
