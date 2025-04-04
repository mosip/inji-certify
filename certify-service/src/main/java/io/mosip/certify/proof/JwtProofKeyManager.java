/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.proof;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;

import java.util.Optional;
// Should this method be an abstract class instead of an interface for managing holder's key in JWK format?
/**
 * {@link JwtProofKeyManager} helps in managing the holder's key.
 */
public interface JwtProofKeyManager {
    /**
     * getKeyFromHeader is a method that returns the JWK from the JWSHeader.
     * @param header is the JWSHeader, where the pub key can be in kid or in jwk form
     * @return the JWK
     */
    // TODO: name this method better, maybe getKey(JWSHeader)
    public Optional<JWK> getKeyFromHeader(JWSHeader header);

    /**
     * @param header is the JWSHeader, where the pub key can be in kid or in jwk form
     * @return the DID form of the key
     */
    public Optional<String> getDID(JWSHeader header);
}
