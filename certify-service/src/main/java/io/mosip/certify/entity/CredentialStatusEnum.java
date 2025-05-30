package io.mosip.certify.entity;

/**
 * Enum representing the status of a credential status list
 */
public enum CredentialStatusEnum {
    AVAILABLE("available"),
    FULL("full");

    private final String value;

    CredentialStatusEnum(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static CredentialStatusEnum fromValue(String value) {
        for (CredentialStatusEnum status : CredentialStatusEnum.values()) {
            if (status.value.equals(value)) {
                return status;
            }
        }
        throw new IllegalArgumentException("Unknown credential status: " + value);
    }
}