package io.mosip.certify.core.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Response DTO containing credential status information
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CredentialFetchResponse {

//    /**
//     * The ID of the credential
//     */
//    private String credentialId;

    /**
     * The purpose of the status entry (e.g., "revocation", "suspension")
     */
    private String statusPurpose;

    /**
     * The index in the status list
     */
    private String statusListIndex;

    /**
     * The URL of the status list credential
     */
    private String statusListCredential;
//
//    /**
//     * The current status of the credential (e.g., "valid", "revoked", "suspended")
//     */
//    private String credentialStatus;
//
//    /**
//     * The reason for revocation (if applicable)
//     */
//    private String revocationReason;
//
//    /**
//     * The timestamp when the credential was revoked (if applicable)
//     */
//    private LocalDateTime revocationTimestamp;
//
//    /**
//     * The date when the credential was issued
//     */
//    private LocalDateTime issueDate;
//
//    /**
//     * The date when the credential will expire (if applicable)
//     */
//    private LocalDateTime expirationDate;
}