/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.constants;

public class ErrorConstants {

    public static final String INVALID_METADATA_DISPLAY = "INVALID_METADATA_DISPLAY";
    public static final String INVALID_AUTH_TOKEN = "INVALID_TOKEN";
    public static final String INVALID_ALGORITHM = "INVALID_ALGORITHM";
    public static final String UNKNOWN_ERROR = "UNKNOWN_ERROR";
    public static final String INVALID_VC_FORMAT = "INVALID_VC_FORMAT";
    public static final String UNSUPPORTED_PROOF_TYPE = "UNSUPPORTED_PROOF_TYPE";
    public static final String VC_ISSUANCE_FAILED = "VC_ISSUANCE_FAILED";
    public static final String PROOF_HEADER_INVALID_TYP = "PROOF_HEADER_INVALID_TYP";
    public static final String PROOF_HEADER_INVALID_ALG = "PROOF_HEADER_INVALID_ALG";
    public static final String PROOF_HEADER_INVALID_KEY = "PROOF_HEADER_INVALID_KEY";
    public static final String PROOF_HEADER_AMBIGUOUS_KEY = "PROOF_HEADER_AMBIGUOUS_KEY";
    public static final String UNSUPPORTED_OPENID_VERSION = "UNSUPPORTED_OPENID4VCI_VERSION";
    public static final String INVALID_TEMPLATE_ID = "TEMPLATE_WITH_ID_NOT_FOUND";
    public static final String EMPTY_TEMPLATE_CONTENT = "EMPTY_TEMPLATE_CONTENT";
    public static final String EXPECTED_TEMPLATE_NOT_FOUND = "EXPECTED_TEMPLATE_NOT_FOUND";
    public static final String UNSUPPORTED_IN_CURRENT_PLUGIN_MODE = "UNSUPPORTED_IN_CURRENT_PLUGIN_MODE";
    public static final String UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM";
    public static final String INVALID_CERTIFICATE = "INVALID_CERTIFICATE";
    public static final String VERIFICATION_METHOD_GENERATION_FAILED = "VERIFICATION_METHOD_GENERATION_FAILED";
    public static final String MISSING_APPLICATION_OR_REFERENCE_ID = "MISSING_APPLICATION_OR_REFERENCE_ID";
    public static final String INVALID_CONFIG_REQUEST = "INVALID_CONFIG_REQUEST";
    public static final String STATUS_LIST_NOT_FOUND = "STATUS_LIST_NOT_FOUND_FOR_THE_GIVEN_ID";
    public static final String STATUS_RETRIEVAL_ERROR = "ERROR_PARSING_STATUS_LIST_CREDENTIAL_DOCUMENT";
    public static final String INDEX_OUT_OF_BOUNDS = "REQUESTED_INDEX_IS_OUT_OF_BOUNDS_FOR_STATUS_LIST_CAPACITY";
    public static final String INVALID_FRAGMENT = "INVALID_FRAGMENT_FORMAT_MUST_BE_A_VALID_NUMBER";
    public static final String VC_RESIGNING_FAILED = "VC_RESIGNING_FAILED";
    public static final String BATCH_JOB_EXECUTION_FAILED = "BATCH_JOB_EXECUTION_FAILED";
    public static final String KEY_ALIAS_NOT_CONFIGURED = "KEY_ALIAS_NOT_CONFIGURED";
    public static final String STATUS_LIST_GENERATION_JSON_ERROR = "STATUS_LIST_GENERATION_JSON_ERROR";
    public static final String STATUS_LIST_GENERATION_FAILED = "STATUS_LIST_GENERATION_FAILED";
    public static final String STATUS_LIST_UPDATE_FAILED = "STATUS_LIST_UPDATE_FAILED";
    public static final String TRANSACTION_FETCH_FAILED = "TRANSACTION_FETCH_FAILED";
    public static final String ENCODED_LIST_UPDATE_FAILED = "ENCODED_LIST_UPDATE_FAILED";
    public static final String STATUS_LIST_CREDENTIAL_UPDATE_FAILED = "STATUS_LIST_CREDENTIAL_UPDATE_FAILED";
    public static final String STATUS_LIST_INDEX_INITIALIZATION_FAILED = "STATUS_LIST_INDEX_INITIALIZATION_FAILED";
    public static final String STATUS_LIST_INDEX_UNAVAILABLE = "STATUS_LIST_INDEX_UNAVAILABLE";
    public static final String STATUS_LIST_CAPACITY_MISCONFIGURED = "STATUS_LIST_CAPACITY_MISCONFIGURED";
    public static final String INVALID_ENCODED_LIST = "INVALID_ENCODED_LIST";
    public static final String CANONICALIZATION_ERROR = "CANONICALIZATION_ERROR";
    public static final String CRYPTOSUITE_INITIALIZATION_ERROR = "CRYPTOSUITE_INITIALIZATION_ERROR";
    public static final String VC_SIGNING_ERROR = "VC_SIGNING_ERROR";
    public static final String SEARCH_CREDENTIALS_FAILED = "SEARCH_CREDENTIALS_FAILED";
    public static final String INVALID_SEARCH_CRITERIA = "INVALID_SEARCH_CRITERIA";
    public static final String LEDGER_ENTRY_FAILED = "LEDGER_ENTRY_FAILED";
    public static final String MISSING_CREDENTIAL_STATUS_DETAILS = "MISSING_CREDENTIAL_STATUS_DETAILS";
    public static final String STATUS_ID_MISMATCH = "STATUS_ID_MISMATCH";
    public static final String JSON_PROCESSING_ERROR = "JSON_PROCESSING_ERROR";
    public static final String SD_CLAIMS_PARSE_ERROR = "SD_CLAIMS_PARSE_ERROR";
    public static final String MULTIPLE_STATUS_PURPOSES_NOT_SUPPORTED = "MULTIPLE_STATUS_PURPOSES_NOT_SUPPORTED";
    public static final String INVALID_STATUS_PURPOSE = "INVALID_STATUS_PURPOSE";
    public static final String CREDENTIAL_TEMPLATE_REQUIRED = "CREDENTIAL_TEMPLATE_REQUIRED";
    public static final String LDP_VC_MANDATORY_FIELDS_MISSING = "LDP_VC_MANDATORY_FIELDS_MISSING";
    public static final String LDP_VC_CONFIG_EXISTS = "LDP_VC_CONFIG_EXISTS";
    public static final String MSO_MDOC_MANDATORY_FIELDS_MISSING = "MSO_MDOC_MANDATORY_FIELDS_MISSING";
    public static final String MSO_MDOC_CONFIG_EXISTS = "MSO_MDOC_CONFIG_EXISTS";
    public static final String VC_SD_JWT_MANDATORY_FIELDS_MISSING = "VC_SD_JWT_MANDATORY_FIELDS_MISSING";
    public static final String VC_SD_JWT_CONFIG_EXISTS = "VC_SD_JWT_CONFIG_EXISTS";
    public static final String UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT";
    public static final String UNSUPPORTED_CRYPTO_SUITE = "UNSUPPORTED_CRYPTO_SUITE";
    public static final String UNSUPPORTED_SIGNATURE_ALGO = "UNSUPPORTED_SIGNATURE_ALGO";
    public static final String KEY_CHOOSER_CONFIG_NOT_FOUND = "KEY_CHOOSER_CONFIG_NOT_FOUND";
    public static final String KEY_CHOOSER_APP_REF_NOT_FOUND = "KEY_CHOOSER_APP_REF_NOT_FOUND";
    public static final String CONFIG_NOT_FOUND_BY_ID = "CONFIG_NOT_FOUND_BY_ID";
    public static final String CONFIG_NOT_ACTIVE = "CONFIG_NOT_ACTIVE";
    public static final String CONFIG_NOT_FOUND_FOR_UPDATE = "CONFIG_NOT_FOUND_FOR_UPDATE";
    public static final String CONFIG_NOT_FOUND_FOR_DELETE = "CONFIG_NOT_FOUND_FOR_DELETE";
    public static final String INVALID_CREDENTIAL_CONFIGURATION_ID = "invalid_credential_configuration_id";
    public static final String MISSING_MANDATORY_CLAIM = "missing_mandatory_claim";
    public static final String CREDENTIAL_OFFER_NOT_FOUND = "credential_offer_not_found";
    public static final String UNKNOWN_CLAIMS = "unknown_claims";
    public static final String INVALID_EXPIRY_RANGE = "invalid_expiry_range";
    public static final String INVALID_OFFER_ID_FORMAT = "invalid_offer_id_format";
}
