package io.mosip.certify.services.entity;

import lombok.*;

import java.io.Serializable;
import java.util.Objects;

@NoArgsConstructor
@AllArgsConstructor
public class TemplateId implements Serializable {
    @Getter
    @Setter
    private String context;
    @Getter
    @Setter
    private String credentialType;

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
