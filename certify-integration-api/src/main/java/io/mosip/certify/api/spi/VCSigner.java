package io.mosip.certify.api.spi;

import io.mosip.certify.api.dto.VCResult;
import org.json.JSONObject;

/**
 * VCSigner can sign any VC provided a vcHash & Signer inputs
 */
public interface VCSigner {
    VCResult<?> perform(JSONObject templatedVC);
}
