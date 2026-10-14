package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.utils.SDJsonUtils;

/**
 * Validates the selective disclosure paths configured in {@code sdClaim} when a credential
 * configuration is added or updated.
 *
 * <p>Only what can be decided from the configured string is checked: a blank entry, or an entry that is
 * not a well formed path. Whether a path exists in the credential needs the holder's data, so that check
 * stays at VC fetch, in {@code SDJWT.createCredential}.
 */
public class SdClaimValidator {

    private SdClaimValidator() {
    }

    /**
     * @param sdClaim the comma separated paths as configured, or null when the configuration declares no
     *                selective disclosure
     * @throws CertifyException with {@link ErrorConstants#INVALID_SD_CLAIM} for the first entry that is
     *                          blank or not a well formed selective disclosure path
     */
    public static void validateSdClaim(String sdClaim) {
        if (sdClaim == null) {
            return;
        }
        // The -1 limit keeps trailing empty entries. A plain split(",") reads "$.fullName," as one valid
        // path and "," as no paths at all, so both would pass.
        for (String entry : sdClaim.split(",", -1)) {
            if (entry.isBlank()) {
                throw new CertifyException(ErrorConstants.INVALID_SD_CLAIM,
                        "The sdClaim '" + sdClaim + "' contains a blank entry.");
            }
            if (!SDJsonUtils.isPathSyntaxValid(entry)) {
                throw new CertifyException(ErrorConstants.INVALID_SD_CLAIM,
                        "The sdClaim entry '" + entry.trim() + "' is not a valid selective disclosure path,"
                                + " such as $.fullName, $.address.region, $.phoneNumbers[0] or $.phoneNumbers[*].");
            }
        }
    }
}
