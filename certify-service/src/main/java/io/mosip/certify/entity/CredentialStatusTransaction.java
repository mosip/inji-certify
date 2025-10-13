package io.mosip.certify.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "credential_status_transaction")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CredentialStatusTransaction {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "transaction_log_id")
    private Long transactionLogId;

    @Column(name = "credential_id", length = 255)
    private String credentialId;

    @Column(name = "status_purpose", length = 100)
    private String statusPurpose;

    @Column(name = "status_value")
    private Boolean statusValue;

    @Column(name = "status_list_credential_id", length = 255)
    private String statusListCredentialId;

    @Column(name = "status_list_index")
    private Long statusListIndex;

    @Column(name = "cr_dtimes", nullable = false, updatable = false)
    private LocalDateTime createdDtimes;

    @Column(name = "processed_dtimes")
    private LocalDateTime processedTime;

    @Column(name = "is_processed", nullable = false)
    private Boolean isProcessed = Boolean.FALSE;

    @PrePersist
    protected void onCreate() {
        createdDtimes = LocalDateTime.now();
        if (isProcessed == null) {
            isProcessed = Boolean.FALSE;
        }
    }
}