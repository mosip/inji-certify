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

class TemplateId implements Serializable {
    private String context;
    private String credentialType;

    public TemplateId(String context, String credentialType) {
        this.context = context;
        this.credentialType = credentialType;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TemplateId that)) return false;
        return Objects.equals(context, that.context) && Objects.equals(credentialType, that.credentialType);
    }

    @Override
    public int hashCode() {
        return Objects.hash(context, credentialType);
    }
}