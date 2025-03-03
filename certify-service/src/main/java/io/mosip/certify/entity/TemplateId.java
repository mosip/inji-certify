package io.mosip.certify.entity;

import java.io.Serializable;
import java.util.Objects;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
public class TemplateId implements Serializable {
    @Getter
    @Setter
    private String context;
    @Getter
    @Setter
    private String credentialType;
    @Getter
    @Setter
    private String credentialFormat;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TemplateId that)) return false;
        return Objects.equals(context, that.context) && Objects.equals(credentialType, that.credentialType) && Objects.equals(credentialFormat, that.credentialFormat);
    }

    @Override
    public int hashCode() {
        return Objects.hash(context, credentialType, credentialFormat);
    }
}
