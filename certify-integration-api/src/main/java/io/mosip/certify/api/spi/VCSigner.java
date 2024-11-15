package io.mosip.certify.api.spi;

import io.mosip.certify.api.dto.VCResult;

/**
 * VCSigner can sign any VC provided a vcHash & Signer inputs
 */
public interface VCSigner {
    VCResult<?> perform(String templatedVC);
}
