package io.mosip.certify.services.spi;

import io.mosip.certify.api.dto.VCResult;

/**
 * VCSigner can sign any JSON-LD VC provided a vcHash & Signer inputs and
 *  return a signed VCResult.
 */
public interface VCSigner {
    VCResult<?> attachSignature(String unSignedVC);
}
