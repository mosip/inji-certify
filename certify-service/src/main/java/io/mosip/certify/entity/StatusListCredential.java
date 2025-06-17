package io.mosip.certify.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "status_list_credential", indexes = {
        @Index(name = "idx_slc_status_purpose", columnList = "status_purpose")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class StatusListCredential {

    @Id
    @Column(length = 255)
    private String id;

//    @Lob
    @Column(name = "vc_document", columnDefinition = "TEXT", nullable = false)
    private String vcDocument;
//    private byte[] vcDocument;

    @Column(name = "credential_type", length = 100, nullable = false)
    private String credentialType;

    @Column(name = "status_purpose", length = 100)
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

    public enum CredentialStatus {
        AVAILABLE("available"),
        FULL("full");

        private final String value;

        CredentialStatus(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }
}