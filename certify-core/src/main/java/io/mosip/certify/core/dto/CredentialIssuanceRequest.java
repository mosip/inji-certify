///*
// * This Source Code Form is subject to the terms of the Mozilla Public
// * License, v. 2.0. If a copy of the MPL was not distributed with this
// * file, You can obtain one at https://mozilla.org/MPL/2.0/.
// */
//package io.mosip.certify.core.dto;
//
//import io.mosip.certify.core.constants.ErrorConstants;
//import jakarta.validation.Valid;
//import jakarta.validation.constraints.NotBlank;
//import jakarta.validation.constraints.NotNull;
//import lombok.Data;
//
//import java.time.LocalDateTime;
//import java.util.Map;
//
//@Data
//public class CredentialIssuanceRequest {
//
//    /**
//     * REQUIRED. Unique identifier for the credential.
//     */
//    @NotBlank(message = ErrorConstants.INVALID_CREDENTIAL_ID)
//    private String credentialId;
//
//    /**
//     * REQUIRED. Identifier of the issuer.
//     */
//    @NotBlank(message = ErrorConstants.INVALID_ISSUER_ID)
//    private String issuerId;
//
//    /**
//     * REQUIRED. Format of the Credential to be issued.
//     */
//    @NotBlank(message = ErrorConstants.INVALID_VC_FORMAT)
//    private String format;
//
//    /**
//     * REQUIRED. Information about the holder of the credential.
//     */
//    @Valid
//    @NotNull(message = ErrorConstants.INVALID_HOLDER_INFO)
//    private HolderInfo holderInfo;
//
//    /**
//     * OPTIONAL. Expiration date for the credential.
//     */
//    private LocalDateTime expirationDate;
//
//    /**
//     * OPTIONAL. Status information for the credential.
//     */
//    private CredentialStatus credentialStatus;
//
//    /**
//     * OPTIONAL.
//     * JSON object containing proof of possession of the key material the issued Credential shall be bound to.
//     */
//    @Valid
//    private CredentialProof proof;
//
//    /**
//     * REQUIRED. JSON object containing credential definition details.
//     */
//    @Valid
//    @NotNull(message = ErrorConstants.INVALID_CREDENTIAL_DEFINITION)
//    private CredentialDefinition credentialDefinition;
//
//    /**
//     * OPTIONAL. Document type of the credential.
//     */
//    private String doctype;
//
//    /**
//     * REQUIRED. Map containing claim key-value pairs to be included in the credential.
//     */
//    @NotNull(message = ErrorConstants.INVALID_CLAIMS)
//    private Map<String, Object> claims;
//
//}