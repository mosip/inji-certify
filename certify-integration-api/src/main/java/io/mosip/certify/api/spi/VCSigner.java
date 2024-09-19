package io.mosip.certify.api.spi;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCResult;
import java.util.Map;

/**
 * VCSigner can sign any VC provided a vcHash & Signer inputs
 */
public interface VCSigner {
    VCResult<?> perform(String templatedVC, Map<String, String> params);
}
