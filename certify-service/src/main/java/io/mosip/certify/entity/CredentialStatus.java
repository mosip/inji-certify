package io.mosip.certify.entity;

import lombok.Data;

import javax.persistence.*;
import java.time.LocalDateTime;

/**
 * Entity class for credential_status table
 */
@Data
@Entity
@Table(name = "credential_status")
public class CredentialStatus {

    @Id
    @Column(name = "status_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long statusId;

    @Column(name = "ledger_id")
    private String ledgerId;

    @Column(name = "status_purpose")
    private String statusPurpose;

    @Column(name = "status_list_credential_id")
    private String statusListCredentialId;

    @Column(name = "status_list_index")
    private Long statusListIndex;

    @Column(name = "status_value")
    private String statusValue;

    @Column(name = "cr_dtimes")
    private LocalDateTime createdDtimes;

    @Column(name = "upd_dtimes")
    private LocalDateTime updatedDtimes;
}