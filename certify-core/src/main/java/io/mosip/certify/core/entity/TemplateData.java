package io.mosip.certify.core.entity;


import jakarta.persistence.Entity;
import jakarta.persistence.*;
import lombok.*;
import jakarta.validation.constraints.NotBlank;

import java.io.Serializable;
import java.util.Objects;

@Entity
@NoArgsConstructor
@IdClass(TemplateId.class)
public class TemplateData {
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
}

