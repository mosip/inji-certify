package io.mosip.certify.enums;

import io.mosip.certify.core.exception.CertifyException;

import java.util.Arrays;

public enum CredentialStatusPurpose {
    REVOCATION("revocation"),
    SUSPENSION("suspension");

    private final String purpose;

    private CredentialStatusPurpose(String purpose) {
        this.purpose = purpose;
    }

    public static CredentialStatusPurpose fromString(String value) {
        return Arrays.stream(CredentialStatusPurpose.values())
                .filter(suite -> suite.purpose.equals(value))
                .findFirst()
                .orElseThrow(() -> new CertifyException("Invalid credential status purpose: " + value));
    }

    @Override
    public String toString() {
        return purpose;
    }
}