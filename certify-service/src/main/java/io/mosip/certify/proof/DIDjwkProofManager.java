/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.proof;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONException;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;

/**
 * DIDjwkProofManager is a class that implements the JwtProofKeyManager
 *  interface for validating a holder's proof key in did:jwk form.
 */
@Component
@Slf4j
public class DIDjwkProofManager implements JwtProofKeyManager {

    private static final String DID_JWK_PREFIX = "did:jwk:";

    /**
     * Currently only handles did:jwk, Need to handle other methods
     * @param header of jwk in did:jwk format.
     *               ref: https://github.com/quartzjer/did-jwk/blob/main/spec.md#to-create-the-did-url
     * @return the JSON Web Key if a valid key exists
     */
    public Optional<JWK> getKeyFromHeader(JWSHeader header) {
        if(Objects.nonNull(header.getJWK()))
            return Optional.of(header.getJWK());
        String did = header.getKeyID();
        if(did != null && did.startsWith(DID_JWK_PREFIX)) {
            try {
                //Ignoring fragment part as did:jwk only contains single key, the DID URL fragment identifier is always
                //a fixed #0 value. If the JWK contains a kid value it is not used as the reference, #0 is the only valid value.
                String base64JWK = did.split("#")[0].substring(DID_JWK_PREFIX.length());
                // Decode JWK from Base64
                byte[] jwkBytes = Base64.getUrlDecoder().decode(base64JWK);
                String jwkJson = new String(jwkBytes, StandardCharsets.UTF_8);

                // Parse JWK
                // TODO(perf): the below lines make no sense here as did is already present in this if
                org.json.JSONObject jsonKey = new org.json.JSONObject(jwkJson);
                jsonKey.put("kid", did);
                return Optional.of(JWK.parse(jsonKey.toString()));
            } catch (IllegalArgumentException e) {
                log.error("Invalid base64 encoded ID : {}", did, e);
            } catch (ParseException | JSONException e) {
                log.error("Invalid jwk : {}", did, e);
            }
        }
        return Optional.empty();
    }

    /**
     * @param header is the JWSHeader, where the pub key can be in kid or in jwk field
     * @return the key in did:jwk form
     */
    @Override
    public Optional<String> getDID(JWSHeader header) {
        if (header.getJWK() != null) {
            // 1. Convert JWK back to DID:jwk
            byte[] keyBytes = header.getJWK().toJSONString().getBytes(StandardCharsets.UTF_8);
            return Optional.of(DID_JWK_PREFIX.concat(Base64.getUrlEncoder().encodeToString(keyBytes)));
        } else if (header.getKeyID().startsWith(DID_JWK_PREFIX)) {
            return Optional.of(header.getKeyID());
        }
        return Optional.empty();
    }
}
