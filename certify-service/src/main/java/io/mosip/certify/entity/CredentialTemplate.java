package io.mosip.certify.entity;


import java.time.LocalDateTime;

import org.hibernate.annotations.Comment;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@NoArgsConstructor
@Table(name = "credential_template")
@IdClass(TemplateId.class)
public class CredentialTemplate {
    @NotBlank(message = "Template is mandatory")
    @Getter
    @Setter
    private String template;
    @Id
    @Getter
    @Setter
    private String context;
    @Id
    @Getter
    @Setter
    private String credentialType;
    @Id
    @Getter
    @Setter
    private String credentialFormat;
    @Getter
    @Setter
    @Comment("URL for the public key. Should point to the exact key. Supports DID document or public key")
    private String didUrl;
    @Getter
    @Setter
    @Comment("AppId of the keymanager")
    private String keyManagerAppId;
    @Getter
    @Setter
    @Comment("RefId of the keymanager")
    private String keyManagerRefId;
    @Getter
    @Setter
    @Comment("This for VC signature or proof algorithm")
    private String signatureAlgo; //Can be called as Proof algorithm
    @Getter
    @Setter
    @Comment("This is a comma seperated list for selective disclosure.")
    private String sdClaim; 

    @NotBlank
    @Column(name = "cr_dtimes")
    private LocalDateTime createdTimes;

    @Column(name = "upd_dtimes")
    private LocalDateTime updatedTimes;

}
