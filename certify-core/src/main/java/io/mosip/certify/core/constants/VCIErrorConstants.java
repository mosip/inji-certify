/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.constants;

// Error constants specific to the OpenId4VCI Credential Error Response implementation
// Ref : https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-credential-error-response
public class VCIErrorConstants {
    public static final String INVALID_REQUEST = "invalid_request";
    public static final String INVALID_SCOPE = "invalid_scope";
    public static final String INVALID_CREDENTIAL_REQUEST = "invalid_credential_request";
    public static final String UNSUPPORTED_CREDENTIAL_TYPE = "unsupported_credential_type";
    public static final String UNSUPPORTED_CREDENTIAL_FORMAT = "unsupported_credential_format";
    public static final String INVALID_PROOF = "invalid_proof";
}
