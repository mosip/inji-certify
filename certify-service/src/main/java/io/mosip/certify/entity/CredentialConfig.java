package io.mosip.certify.entity;

import jakarta.persistence.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Data
@Entity
@Table(name="credential_config")
public class CredentialConfig {
    @Id
    private String id;

    private String status;

    @NotNull(message = "Invalid request")
    private String vcTemplate;

    @NotNull(message = "Invalid request")
    @Column(name = "context", columnDefinition = "TEXT[]")
    private List<String> context;

    @NotNull(message = "Invalid request")
    @Column(name="credentialType", columnDefinition = "TEXT[]")
    private List<String> credentialType;

    @NotNull(message = "Invalid request")
    private String credentialFormat;

    @NotNull(message = "Invalid request")
    private String didUrl;

    @Valid
    @NotNull(message = "Invalid request")
    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "display_id")
    private CredentialDisplay display;

    @Column(name = "display_order", columnDefinition = "TEXT[]")
    private List<String> order;

    @NotNull(message = "Invalid request")
    private String scope;

    @NotNull(message = "Invalid request")
    @Column(name = "cryptographic_binding_methods_supported", columnDefinition = "TEXT[]")
    private List<String> cryptographicBindingMethodsSupported;

    @NotNull(message = "Invalid request")
    @Column(name = "credential_signing_alg_values_supported", columnDefinition = "TEXT[]")
    private List<String> credentialSigningAlgValuesSupported;

    @NotNull(message = "Invalid request")
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "proof_types_supported", columnDefinition = "jsonb")
    private Map<String, Object> proofTypesSupported;

    @NotNull(message = "Invalid request")
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "credential_subject", columnDefinition = "jsonb")
    private Map<String, Object> credentialSubject;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "plugin_configurations", columnDefinition = "jsonb")
    private List<Map<String, String>> pluginConfigurations;

    @NotNull
    @Column(name = "cr_dtimes")
    private LocalDateTime createdTime;

    @Column(name = "upd_dtimes")
    private LocalDateTime updatedTime;
}
