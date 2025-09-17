package io.mosip.certify.entity;

import io.mosip.certify.entity.attributes.CredentialStatusDetail;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Ledger {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "credential_id", length = 255, unique = true)
    private String credentialId;

    @Column(name = "issuer_id", length = 255, nullable = false)
    private String issuerId;

    @Column(name = "issue_date", nullable = false)
    private OffsetDateTime issueDate;

    @Column(name = "expiration_date")
    private OffsetDateTime expirationDate;

    @Column(name = "credential_type", length = 100, nullable = false)
    private String credentialType;

    @Column(name = "indexed_attributes")
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> indexedAttributes;

    @Column(name = "credential_status_details")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<CredentialStatusDetail> credentialStatusDetails;

    @Column(name = "cr_dtimes", nullable = false, updatable = false)
    private LocalDateTime createdDtimes;

    @PrePersist
    protected void onCreate() {
        createdDtimes = LocalDateTime.now();
        if (credentialStatusDetails == null) {
            credentialStatusDetails = List.of();
        }
    }
}