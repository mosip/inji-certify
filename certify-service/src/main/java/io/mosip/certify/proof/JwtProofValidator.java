/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.proof;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.CredentialProof;
import io.mosip.certify.core.exception.InvalidRequestException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.*;

@Slf4j
@Component
public class JwtProofValidator implements ProofValidator {

    private static final String HEADER_TYP = "openid4vci-proof+jwt";
    private static final String DID_JWK_PREFIX = "did:jwk:";

    @Value("#{${mosip.certify.supported.jwt-proof-alg}}")
    private List<String> supportedAlgorithms;

    @Value("${mosip.certify.identifier}")
    private String credentialIdentifier;

    @Override
    public String getProofType() {
        return "jwt";
    }

    private static final Set<JWSAlgorithm> allowedSignatureAlgorithms;

    private static final Set<String> DEFAULT_REQUIRED_CLAIMS = Set.of("aud", "iat");

    static {
        allowedSignatureAlgorithms = new HashSet<>();
        allowedSignatureAlgorithms.addAll(List.of(JWSAlgorithm.Family.SIGNATURE.toArray(new JWSAlgorithm[0])));
    }

    @Override
    public boolean validate(String clientId, String cNonce, CredentialProof credentialProof) {
        if(credentialProof.getJwt() == null || credentialProof.getJwt().isBlank()) {
            log.error("Found invalid jwt in the credential proof");
            return false;
        }

        try {
            SignedJWT jwt = (SignedJWT) JWTParser.parse(credentialProof.getJwt());
            validateHeaderClaims(jwt.getHeader());
            JwtProofKeyManager jpkm = getInstance(jwt.getHeader().getKeyID());
            JWK jwk = jpkm.getKeyFromHeader(jwt.getHeader())
                    .orElseThrow(() -> new InvalidRequestException(ErrorConstants.PROOF_HEADER_AMBIGUOUS_KEY));
            if(jwk.isPrivate()) {
                log.error("Provided key material contains private key! Rejecting proof.");
                throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_KEY);
            }

            JWTClaimsSet.Builder proofJwtClaimsBuilder = new JWTClaimsSet.Builder()
                    .audience(credentialIdentifier)
                    .claim("nonce", cNonce);

            // if the proof contains issuer claim, then it should match with the client id ref: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-7.2.1.1-2.2.2.1
            // https://github.com/openid/OpenID4VCI/issues/349
            Set<String> requiredClaims = new HashSet<>(DEFAULT_REQUIRED_CLAIMS);
            if(jwt.getJWTClaimsSet().getClaim("iss") != null) {
                proofJwtClaimsBuilder.issuer(clientId);
            }
            if(jwt.getJWTClaimsSet().getClaim("exp") != null) {
                requiredClaims.add("exp");
            }

            DefaultJWTClaimsVerifier claimsSetVerifier = new DefaultJWTClaimsVerifier(proofJwtClaimsBuilder.build(), requiredClaims);

            claimsSetVerifier.setMaxClockSkew(0);
            JWSKeySelector keySelector;
            if(JWSAlgorithm.ES256K.equals(jwt.getHeader().getAlgorithm())) {
                ECDSAVerifier verifier = new ECDSAVerifier((com.nimbusds.jose.jwk.ECKey) jwk);
                verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
                boolean verified = jwt.verify(verifier);
                claimsSetVerifier.verify(jwt.getJWTClaimsSet(), null);
                return verified;
            } else if (JWSAlgorithm.Ed25519.equals(jwt.getHeader().getAlgorithm())) {
                Ed25519Verifier verifier = new Ed25519Verifier(jwk.toOctetKeyPair());
                boolean verified = jwt.verify(verifier);
                claimsSetVerifier.verify(jwt.getJWTClaimsSet(), null);
                return verified;
            } else {
                keySelector = new JWSVerificationKeySelector(allowedSignatureAlgorithms,
                        new ImmutableJWKSet(new JWKSet(jwk)));
                ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
                jwtProcessor.setJWSKeySelector(keySelector);
                jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier(new JOSEObjectType(HEADER_TYP)));
                jwtProcessor.setJWTClaimsSetVerifier(claimsSetVerifier);
                jwtProcessor.process(credentialProof.getJwt(), null);
                return true;
            }
        } catch (InvalidRequestException e) {
            log.error("Invalid proof : {}", e.getErrorCode());
        } catch (ParseException e) {
            log.error("Failed to parse jwt in the credential proof", e);
        } catch (BadJOSEException | JOSEException e) {
            log.error("JWT proof verification failed", e);
        }
        return false;
    }

    /**
     * @param credentialProof proof from the credential request.
     * @return the key material from the proof in a did:jwk or did:key format
     */
    @Override
    public String getKeyMaterial(CredentialProof credentialProof) {
        try {
            SignedJWT jwt = (SignedJWT) JWTParser.parse(credentialProof.getJwt());
            JwtProofKeyManager jpkm = getInstance(jwt.getHeader().getKeyID());
            return jpkm.getDID(jwt.getHeader()).get();
        } catch (ParseException e) {
            log.error("Failed to parse jwt in the credential proof", e);
        } catch (InvalidRequestException e) {
            log.error("Invalid proof : {}", e.getErrorCode());
        }
        throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_KEY);
    }

    private void validateHeaderClaims(JWSHeader jwsHeader) {
        if(Objects.isNull(jwsHeader.getType()) || !HEADER_TYP.equals(jwsHeader.getType().getType()))
            throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_TYP);

        if(Objects.isNull(jwsHeader.getAlgorithm()) || !supportedAlgorithms.contains(jwsHeader.getAlgorithm().getName()))
            throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_ALG);

        if(Objects.isNull(jwsHeader.getKeyID()) && Objects.isNull(jwsHeader.getJWK()))
            throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_INVALID_KEY);

        //both cannot be present, either one of them is only allowed
        if(Objects.nonNull(jwsHeader.getKeyID()) && Objects.nonNull(jwsHeader.getJWK()))
            throw new InvalidRequestException(ErrorConstants.PROOF_HEADER_AMBIGUOUS_KEY);

        //TODO x5c and trust_chain validation
    }

    public JwtProofKeyManager getInstance(String kid) {
        if (kid == null || kid.startsWith(DID_JWK_PREFIX)) {
            return new DIDjwkProofManager();
        } else if (kid.startsWith("did:key:")) {
            return new DIDkeysProofManager();
        } else {
            return new DIDjwkProofManager();
        }
    }
}