package io.mosip.certify.core.entity;


import jakarta.persistence.Entity;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import jakarta.validation.constraints.NotBlank;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Objects;

@Data
@Entity
@NoArgsConstructor
@AllArgsConstructor
@IdClass(TemplateId.class)
public class TemplateData {
    @NotBlank(message = "Template is mandatory")
    private String template;
    @Id
    private String context;
    @Id
    private String credentialType;
}

