package io.mosip.certify.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "credential_status")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CredentialStatus {
    @Id
    @Column(name = "id", nullable = false)
    private String id;
    
    @Column(name = "credential_id", nullable = false)
    private String credentialId;
    
    @Column(name = "issuer_id", nullable = false)
    private String issuerId;
    
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
    
    @Column(name = "cr_by", nullable = false)
    private String createdBy;
    
    @Column(name = "cr_dtimes", nullable = false)
    private LocalDateTime createdTimes;
    
    @Column(name = "upd_by")
    private String updatedBy;
    
    @Column(name = "upd_dtimes")
    private LocalDateTime updatedTimes;
    
    @Column(name = "is_deleted", columnDefinition = "BOOLEAN DEFAULT FALSE")
    private Boolean isDeleted;
    
    @Column(name = "del_dtimes")
    private LocalDateTime deletedTimes;
    
    @OneToMany(mappedBy = "credentialStatus", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private java.util.Set<CredentialHolder> credentialHolders;
}