package io.mosip.certify.enums;

/**
 * Enum for credential format as per the OpenID4VCI
 */
public enum CredentialFormat {
    VC_SD_JWT("vc+sd-jwt"),
    SD_JWT("sd-jwt"),
    VC_LDP("ldp_vc");

    private final String format;

    private CredentialFormat(String inputFormat) {
        format = inputFormat;
    }

    public boolean equalsName(String otherFormat) {
        // (otherFormat == null) check is not needed because format.equals(null) returns false 
        return format.equals(otherFormat);
    }

    @Override
    public String toString() {
       return this.format;
    }
}
