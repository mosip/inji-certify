package io.mosip.certify.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;

@Entity
@Table(name = "ledger_issuance_table")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class LedgerIssuanceTable {
    @Id
    @Column(name = "id", nullable = false)
    private String id;

    @Column(name = "credential_id", nullable = false)
    private String credentialId;

    @Column(name = "issuer_id", nullable = false)
    private String issuerId;

    @Column(name = "holder_id", nullable = false)
    private String holderId;

    @Column(name = "type", nullable = false, columnDefinition = "VARCHAR(50) DEFAULT 'BitstringStatusListEntry'")
    private String type = "BitstringStatusListEntry";

    @Column(name = "status_list_index", nullable = false)
    private Long statusListIndex;

    @Column(name = "status_list_credential", nullable = false)
    private String statusListCredential;

    @Column(name = "status_purpose", nullable = false)
    private String statusPurpose;

    @Column(name = "credential_status", nullable = false, columnDefinition = "VARCHAR(50) DEFAULT 'valid'")
    private String credentialStatus = "valid";

    @Column(name = "status_size", columnDefinition = "integer DEFAULT 1")
    private Integer statusSize = 1;

    @Column(name = "status_message", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private String statusMessage;

    @Column(name = "status_reference", length = 512)
    private String statusReference;

    @Column(name = "issue_date", nullable = false)
    private LocalDateTime issueDate;

    @Column(name = "expiration_date")
    private LocalDateTime expirationDate;

    @Column(name = "revocation_timestamp")
    private LocalDateTime revocationTimestamp;

    @Column(name = "revocation_reason")
    private String revocationReason;

    @Column(name = "revocation_proof", length = 512)
    private String revocationProof;

    @Column(name = "credential_subject_hash", nullable = false, unique = true)
    private String credentialSubjectHash;
}