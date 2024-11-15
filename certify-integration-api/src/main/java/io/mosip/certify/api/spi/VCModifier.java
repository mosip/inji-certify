package io.mosip.certify.api.spi;

import org.json.JSONObject;

/**
 * VCModifier is a modifier which takes @param templateInput and
 * returns a modified VC as per configuration.
 *
 * Some implementations include
 * - add an id which is a UUID
 *
 * Future possible implementations:
 * - Support for SD-JWT
 * - Support for additional validations
 */
public interface VCModifier {
    JSONObject perform(String templateInput);
}
