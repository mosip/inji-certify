package io.mosip.certify.entity;


import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import io.hypersistence.utils.hibernate.type.json.JsonBinaryType;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.hibernate.annotations.Comment;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.Type;
import org.hibernate.type.SqlTypes;

@Data
@Entity
@NoArgsConstructor
@Table(name = "credential_config")
@IdClass(TemplateId.class)
public class CredentialConfig {

    private String configId;

    private String status;

    private String vcTemplate;

    @Id
    private String context;

    @Id
    private String credentialType;

    @Id
    private String credentialFormat;

    @Comment("URL for the public key. Should point to the exact key. Supports DID document or public key")
    private String didUrl;

    @Comment("AppId of the keymanager")
    private String keyManagerAppId;

    @Comment("RefId of the keymanager")
    private String keyManagerRefId;

    @Comment("This for VC signature or proof algorithm")
    private String signatureAlgo; //Can be called as Proof algorithm

    @Comment("This is a comma seperated list for selective disclosure.")
    private String sdClaim;

    @NotNull(message = "Invalid request")
    @Type(JsonBinaryType.class)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "display", columnDefinition = "jsonb")
    private List<Map<String, Object>> display;

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
    @Type(JsonBinaryType.class)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "proof_types_supported", columnDefinition = "jsonb")
    private Map<String, Object> proofTypesSupported;

    @Column(name = "doctype")
    private String docType;

    @Type(JsonBinaryType.class)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "credential_subject", columnDefinition = "jsonb")
    private Map<String, Object> credentialSubject;

    @Type(JsonBinaryType.class)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "claims", columnDefinition = "jsonb")
    private Map<String, Object> claims;

    @Type(JsonBinaryType.class)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "plugin_configurations", columnDefinition = "jsonb")
    private List<Map<String, String>> pluginConfigurations;

    @NotNull
    @Column(name = "cr_dtimes")
    private LocalDateTime createdTimes;

    @Column(name = "upd_dtimes")
    private LocalDateTime updatedTimes;

}
