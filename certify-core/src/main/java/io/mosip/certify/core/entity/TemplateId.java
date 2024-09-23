package io.mosip.certify.core.entity;

import java.io.Serializable;
import java.util.Objects;

public class TemplateId implements Serializable {
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
