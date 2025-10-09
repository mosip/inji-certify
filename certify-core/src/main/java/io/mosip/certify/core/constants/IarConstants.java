/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.constants;

/**
 * Constants for Interactive Authorization Request (IAR) functionality
 */
public class IarConstants {

    // IAR Status values
    public static final String STATUS_REQUIRE_INTERACTION = "require_interaction";
    public static final String STATUS_OK = "ok";
    public static final String STATUS_ERROR = "error";
    
    // IAR Type values
    public static final String OPENID4VP_PRESENTATION = "openid4vp_presentation";

    // OAuth 2.0 Response Types
    public static final String RESPONSE_TYPE_CODE = "code";

    // OAuth 2.0 Grant Types
    public static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
    public static final String GRANT_TYPE_PRE_AUTHORIZED_CODE = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    public static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";

    // PKCE Code Challenge Methods
    public static final String CODE_CHALLENGE_METHOD_S256 = "S256";

    // OpenID4VP Response Modes
    public static final String RESPONSE_MODE_IAR_POST = "iar-post";
    public static final String RESPONSE_MODE_IAR_POST_JWT = "iar-post.jwt";

    // Interaction Types
    public static final String INTERACTION_TYPE_OPENID4VP = "openid4vp_presentation";
    public static final String INTERACTION_TYPE_REDIRECT_TO_WEB = "redirect_to_web";


    // Content Types
    public static final String CONTENT_TYPE_FORM_URLENCODED = "application/x-www-form-urlencoded";
    public static final String CONTENT_TYPE_JSON = "application/json";

    // Error codes
    public static final String INVALID_REQUEST = "invalid_request";
    public static final String UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
    public static final String UNSUPPORTED_INTERACTION_TYPE = "unsupported_interaction_type";
    public static final String INVALID_CLIENT = "invalid_client";
    public static final String INTERACTION_REQUIRED = "interaction_required";
    public static final String INVALID_AUTH_SESSION = "invalid_auth_session";
}
