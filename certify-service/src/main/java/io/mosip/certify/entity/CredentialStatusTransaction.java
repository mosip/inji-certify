package io.mosip.certify.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.time.LocalDateTime;

/**
 * Entity class for credential_status_transaction table
 * Represents a transaction to update the status of a credential
 */
@Data
@Entity
@Table(name = "credential_status_transaction")
@NoArgsConstructor
@AllArgsConstructor
public class CredentialStatusTransaction {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "transaction_log_id")
    private Long transactionLogId;

    @Column(name = "credential_id", nullable = false)
    private String credentialId;

    @Column(name = "status_purpose")
    private String statusPurpose;

    @Column(name = "status_value")
    private Boolean statusValue;

    @Column(name = "status_list_credential_id")
    private String statusListCredentialId;

    @Column(name = "status_list_index")
    private Long statusListIndex;

    @Column(name = "cr_dtimes", nullable = false)
    private LocalDateTime createdDtimes;

    @Column(name = "upd_dtimes")
    private LocalDateTime updatedDtimes;
}