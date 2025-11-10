package io.mosip.certify.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcType;
import org.hibernate.dialect.type.PostgreSQLEnumJdbcType;

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
    @Column()
    private String id;

    @Column(name = "vc_document", columnDefinition = "TEXT", nullable = false)
    private String vcDocument;


    @Column(name = "credential_type", length = 100, nullable = false)
    private String credentialType;

    @Column(name = "status_purpose", length = 100)
    private String statusPurpose;

    @Column(name = "capacity_in_kb")
    private Long capacityInKB;

    @Column(name = "credential_status")
    @Enumerated(EnumType.STRING)
    @JdbcType(PostgreSQLEnumJdbcType.class)
    private CredentialStatus credentialStatus;

    @Column(name = "cr_dtimes", nullable = false, updatable = false)
    private LocalDateTime createdDtimes;

    @Column(name = "upd_dtimes")
    private LocalDateTime updatedDtimes;

    public enum CredentialStatus {
        AVAILABLE,
        FULL;
    }
}