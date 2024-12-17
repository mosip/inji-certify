package io.mosip.certify.vcsigners;

import io.mosip.certify.api.dto.VCResult;

import java.util.Map;

/**
 * VCSigner can sign any JSON-LD VC provided a vcHash & Signer inputs and
 *  return a signed VCResult.
 */
public interface VCSigner {
    VCResult<?> attachSignature(String unSignedVC, Map<String, String> keyReferenceDetails);
}
