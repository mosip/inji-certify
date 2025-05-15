// StatusListCredential.java
package io.mosip.certify.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "status_list_credential")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class StatusListCredential {

    @Id
    private String id;

    @Column(name = "vc_document", nullable = false)
    @Lob
    private byte[] vcDocument;

    @Column(name = "credential_type", nullable = false)
    private String credentialType;

    @Column(name = "status_purpose")
    private String statusPurpose;

    @Column(name = "capacity")
    private Long capacity;

    @Column(name = "credential_status")
    @Enumerated(EnumType.STRING)
    private CredentialStatus credentialStatus;

    @Column(name = "cr_dtimes", nullable = false, updatable = false)
    private LocalDateTime createdDtimes;

    @Column(name = "upd_dtimes")
    private LocalDateTime updatedDtimes;

    @PrePersist
    protected void onCreate() {
        createdDtimes = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedDtimes = LocalDateTime.now();
    }

    public enum CredentialStatus {
        AVAILABLE, FULL
    }
}