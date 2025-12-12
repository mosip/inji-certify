/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.constants;

public class ErrorConstants {

    public static final String INVALID_METADATA_DISPLAY = "invalid_metadata_display";
    public static final String INVALID_AUTH_TOKEN = "invalid_token";
    public static final String INVALID_ALGORITHM = "invalid_algorithm";
    public static final String UNKNOWN_ERROR = "unknown_error";
    public static final String INVALID_VC_FORMAT = "invalid_vc_format";
    public static final String UNSUPPORTED_PROOF_TYPE = "unsupported_proof_type";
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
    public static final String MISSING_APPLICATION_OR_REFERENCE_ID = "missing_application_or_reference_id";
    public static final String INVALID_CONFIG_REQUEST = "invalid_config_request";
    public static final String STATUS_LIST_NOT_FOUND = "status_list_not_found_for_the_given_id";
    public static final String STATUS_RETRIEVAL_ERROR = "error_parsing_status_list_credential_document";
    public static final String INDEX_OUT_OF_BOUNDS = "requested_index_is_out_of_bounds_for_status_list_capacity";
    public static final String INVALID_FRAGMENT = "invalid_fragment_format_must_be_a_valid_number";
    public static final String VC_RESIGNING_FAILED = "vc_resigning_failed";
    public static final String BATCH_JOB_EXECUTION_FAILED = "batch_job_execution_failed";
    public static final String KEY_ALIAS_NOT_CONFIGURED = "key_alias_not_configured";
    public static final String STATUS_LIST_GENERATION_JSON_ERROR = "status_list_generation_json_error";
    public static final String STATUS_LIST_GENERATION_FAILED = "status_list_generation_failed";
    public static final String STATUS_LIST_UPDATE_FAILED = "status_list_update_failed";
    public static final String TRANSACTION_FETCH_FAILED = "transaction_fetch_failed";
    public static final String ENCODED_LIST_UPDATE_FAILED = "encoded_list_update_failed";
    public static final String STATUS_LIST_CREDENTIAL_UPDATE_FAILED = "status_list_credential_update_failed";
    public static final String STATUS_LIST_INDEX_INITIALIZATION_FAILED = "status_list_index_initialization_failed";
    public static final String STATUS_LIST_INDEX_UNAVAILABLE = "status_list_index_unavailable";
    public static final String STATUS_LIST_CAPACITY_MISCONFIGURED = "status_list_capacity_misconfigured";
    public static final String INVALID_ENCODED_LIST = "invalid_encoded_list";
    public static final String CANONICALIZATION_ERROR = "canonicalization_error";
    public static final String CRYPTOSUITE_INITIALIZATION_ERROR = "cryptosuite_initialization_error";
    public static final String VC_SIGNING_ERROR = "vc_signing_error";
    public static final String SEARCH_CREDENTIALS_FAILED = "search_credentials_failed";
    public static final String INVALID_SEARCH_CRITERIA = "invalid_search_criteria";
    public static final String LEDGER_ENTRY_FAILED = "ledger_entry_failed";
    public static final String MISSING_CREDENTIAL_STATUS_DETAILS = "missing_credential_status_details";
    public static final String STATUS_ID_MISMATCH = "status_id_mismatch";
    public static final String JSON_PROCESSING_ERROR = "json_processing_error";
    public static final String SD_CLAIMS_PARSE_ERROR = "sd_claims_parse_error";
    public static final String MULTIPLE_STATUS_PURPOSES_NOT_SUPPORTED = "multiple_status_purposes_not_supported";
    public static final String INVALID_STATUS_PURPOSE = "invalid_status_purpose";
    public static final String CREDENTIAL_TEMPLATE_REQUIRED = "credential_template_required";
    public static final String LDP_VC_MANDATORY_FIELDS_MISSING = "ldp_vc_mandatory_fields_missing";
    public static final String LDP_VC_CONFIG_EXISTS = "ldp_vc_config_exists";
    public static final String MSO_MDOC_MANDATORY_FIELDS_MISSING = "mso_mdoc_mandatory_fields_missing";
    public static final String MSO_MDOC_CONFIG_EXISTS = "mso_mdoc_config_exists";
    public static final String VC_SD_JWT_MANDATORY_FIELDS_MISSING = "vc_sd_jwt_mandatory_fields_missing";
    public static final String VC_SD_JWT_CONFIG_EXISTS = "vc_sd_jwt_config_exists";
    public static final String UNSUPPORTED_FORMAT = "unsupported_format";
    public static final String UNSUPPORTED_CRYPTO_SUITE = "unsupported_crypto_suite";
    public static final String UNSUPPORTED_SIGNATURE_ALGO = "unsupported_signature_algo";
    public static final String KEY_CHOOSER_CONFIG_NOT_FOUND = "key_chooser_config_not_found";
    public static final String KEY_CHOOSER_APP_REF_NOT_FOUND = "key_chooser_app_ref_not_found";
    public static final String CONFIG_NOT_FOUND_BY_ID = "config_not_found_by_id";
    public static final String CONFIG_NOT_ACTIVE = "config_not_active";
    public static final String CONFIG_NOT_FOUND_FOR_UPDATE = "config_not_found_for_update";
    public static final String CONFIG_NOT_FOUND_FOR_DELETE = "config_not_found_for_delete";
    public static final String MDOC_TEMPLATE_PROCESSING_FAILED = "mdoc_template_processing_failed";
    public static final String QR_SIGNATURE_ALGO_NOT_ALLOWED = "qr_signature_algo_not_allowed";
    public static final String INVALID_QR_SIGNING_ALGORITHM = "invalid_qr_signing_algorithm";
    public static final String INVALID_CREDENTIAL_CONFIGURATION_ID = "invalid_credential_configuration_id";
    public static final String MISSING_MANDATORY_CLAIM = "missing_mandatory_claim";
    public static final String CREDENTIAL_OFFER_NOT_FOUND = "credential_offer_not_found";
    public static final String UNKNOWN_CLAIMS = "unknown_claims";
    public static final String INVALID_EXPIRY_RANGE = "invalid_expiry_range";
    public static final String INVALID_OFFER_ID_FORMAT = "invalid_offer_id_format";
}
