package io.mosip.certify.entity;


import io.hypersistence.utils.hibernate.type.json.JsonBinaryType;
import io.mosip.certify.entity.attributes.ClaimsDisplayFieldsConfigs;
import io.mosip.certify.entity.attributes.CredentialSubjectParameters;
import io.mosip.certify.entity.attributes.MetaDataDisplay;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Comment;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.Type;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Data
@Entity
@NoArgsConstructor
@Table(name = "credential_config",uniqueConstraints = {
        @UniqueConstraint(name = "uk_credential_config_key_id", columnNames = "credential_config_key_id")
})
public class CredentialConfig {

    @Id
    @Column(name = "config_id", nullable = false, updatable = false)
    private String configId;

    private String status;

    private String vcTemplate;

    @NotNull(message = "Invalid request")
    @Column(name = "credential_config_key_id", unique = true, nullable = false)
    private String credentialConfigKeyId;

    private String context;

    private String credentialType;

    private String credentialFormat;

    @Comment("URL for the public key. Should point to the exact key. Supports DID document or public key")
    private String didUrl;

    @Comment("AppId of the keymanager")
    private String keyManagerAppId;

    @Comment("RefId of the keymanager")
    private String keyManagerRefId;

    @Comment("This for VC signature or proof algorithm")
    private String signatureAlgo; //Can be called as Proof algorithm

    @Comment("This is the crypto suite used for VC signature or proof generation")
    private String signatureCryptoSuite;

    @Comment("This is a comma seperated list for selective disclosure.")
    private String sdClaim;

    @NotNull(message = "Invalid request")
    @Type(JsonBinaryType.class)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "display", columnDefinition = "jsonb")
    private List<MetaDataDisplay> display;

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
    private Map<String, CredentialSubjectParameters> credentialSubject;

    @Type(JsonBinaryType.class)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "mso_mdoc_claims", columnDefinition = "jsonb")
    private Map<String, Map<String, ClaimsDisplayFieldsConfigs>> msoMdocClaims;

    @Type(JsonBinaryType.class)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "sd_jwt_claims", columnDefinition = "jsonb")
    private Map<String, ClaimsDisplayFieldsConfigs> sdJwtClaims;

    @Column(name = "sd_jwt_vct")
    private String sdJwtVct;

    @Type(JsonBinaryType.class)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "plugin_configurations", columnDefinition = "jsonb")
    private List<Map<String, String>> pluginConfigurations;

    @Column(name = "credential_status_purpose", columnDefinition = "TEXT[]")
    private List<String> credentialStatusPurposes;

    @NotNull
    @Column(name = "cr_dtimes")
    private LocalDateTime createdTimes;

    @Column(name = "upd_dtimes")
    private LocalDateTime updatedTimes;
}
