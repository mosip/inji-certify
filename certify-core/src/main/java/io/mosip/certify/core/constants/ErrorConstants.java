/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.constants;

public class ErrorConstants {

    public static final String INVALID_REQUEST="invalid_request";
    public static final String INVALID_SCOPE="invalid_scope";
    public static final String INVALID_AUTH_TOKEN="invalid_token";
    public static final String INVALID_ALGORITHM = "invalid_algorithm";
    public static final String UNKNOWN_ERROR = "unknown_error";
    public static final String UNSUPPORTED_VC_FORMAT = "unsupported_credential_format";
    public static final String INVALID_VC_FORMAT = "invalid_vc_format";
    public static final String INVALID_PROOF = "invalid_proof";
    public static final String UNSUPPORTED_PROOF_TYPE = "unsupported_proof_type";
    public static final String UNSUPPORTED_VC_TYPE = "unsupported_credential_type";
    public static final String VC_ISSUANCE_FAILED = "vc_issuance_failed";
    public static final String PROOF_HEADER_INVALID_TYP = "proof_header_invalid_typ";
    public static final String PROOF_HEADER_INVALID_ALG = "proof_header_invalid_alg";
    public static final String PROOF_HEADER_INVALID_KEY = "proof_header_invalid_key";
    public static final String PROOF_HEADER_AMBIGUOUS_KEY = "proof_header_ambiguous_key";
    public static final String UNSUPPORTED_OPENID_VERSION = "unsupported_openid4vci_version";
    public static final String INVALID_TEMPLATE_ID = "template_with_id_not_found";
    public static final String EMPTY_TEMPLATE_CONTENT = "empty_template_content";
    public static final String EXPECTED_TEMPLATE_NOT_FOUND = "expected_template_not_found";
    public static final String UNSUPPORTED_IN_CURRENT_PLUGIN_MODE = "unsupported_in_current_plugin_mode";
    public static final String UNSUPPORTED_ALGORITHM = "unsupported_algorithm";
    public static final String INVALID_CERTIFICATE = "invalid_certificate";
    public static final String VERIFICATION_METHOD_GENERATION_FAILED = "verification_method_generation_failed";
    public static final String STATUS_LIST_NOT_FOUND = "status_list_not_found_for_the_given_id";
    public static final String STATUS_RETRIEVAL_ERROR = "error_parsing_status_list_credential_document";
    public static final String INDEX_OUT_OF_BOUNDS = "requested_index_is_out_of_bounds_for_status_list_capacity";
    public static final String INVALID_FRAGMENT = "invalid_fragment_format_must_be_a_valid_number";


}
