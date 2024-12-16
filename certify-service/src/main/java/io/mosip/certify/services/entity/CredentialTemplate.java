package io.mosip.certify.services.entity;


import jakarta.persistence.Entity;
import jakarta.persistence.*;
import lombok.*;
import jakarta.validation.constraints.NotBlank;
import java.time.LocalDateTime;

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

    @NotBlank
    @Column(name = "cr_dtimes")
    private LocalDateTime createdTimes;

    @Column(name = "upd_dtimes")
    private LocalDateTime updatedTimes;

}
