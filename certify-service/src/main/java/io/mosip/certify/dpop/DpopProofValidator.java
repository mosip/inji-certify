/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.dpop;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.ParseException;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.mosip.certify.core.exception.InvalidDpopHeaderException;
import io.mosip.certify.core.util.CommonUtil;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

/**
 * Validates a DPoP proof JWT presented in the {@code DPoP} header, per RFC 9449 §4.3.
 *
 * <p>Counterpart of eSignet's {@code DpopValidationFilter}, on the resource-server
 * side. It is a component rather than a filter of its own because
 * {@link io.mosip.certify.filter.AccessTokenValidationFilter} has already decoded and
 * <em>verified</em> the access token by the time this runs, so {@code cnf.jkt} is read
 * from a signature-verified JWT. eSignet reads it from a bare
 * {@code SignedJWT.parse(accessToken)}, which is safe at an authorization server that
 * minted the token itself but not at a resource server.
 *
 * <p>Single-use enforcement of {@code jti} (RFC 9449 §4.3) is the closing step of
 * {@link #validate}, on the same cache contract as eSignet's
 * {@code CacheUtilService.checkAndMarkJti}. Since {@code iat} freshness already bounds how
 * long any proof can be presented, a {@code jti} only has to be remembered for that same
 * window - after it, the proof is rejected on age anyway.
 */
@Slf4j
@Component
public class DpopProofValidator {

    private static final String DPOP_JWT_TYPE = "dpop+jwt";

    private static final String HTM = "htm";
    private static final String HTU = "htu";
    private static final String ATH = "ath";
    private static final String CNF = "cnf";
    private static final String JKT = "jkt";

    static final String DPOP_JTI_CACHE = "dpopJti";

    @Autowired
    private CacheManager cacheManager;

    /**
     * Public address of this issuer, as advertised in the credential issuer metadata.
     *
     * <p>This - not {@code request.getRequestURL()} - is the basis for the {@code htu}
     * check. Certify runs behind a reverse proxy, so the URL Tomcat sees is the internal
     * one, while the wallet signs {@code htu} over the public {@code credential_endpoint}
     * it read from the metadata. Comparing against the container's view would reject
     * every proof in any proxied deployment. eSignet resolves the same problem the same
     * way, from its discovery map rather than the request.
     */
    @Value("${mosip.certify.domain.url}")
    private String domainUrl;

    /**
     * Asymmetric algorithms accepted on the proof. MAC and {@code none} are never allowed.
     *
     * <p>eSignet reads the equivalent list from {@code dpop_signing_alg_values_supported}
     * in its discovery metadata. Certify publishes no protected-resource metadata
     * document to carry that, so it stays a property until it does.
     */
    @Value("${mosip.certify.dpop.allowed-algorithms:ES256,ES384,ES512,RS256,PS256,EdDSA}")
    private List<String> allowedAlgorithms;

    /**
     * The algorithms this validator accepts, for the {@code algs} parameter of a DPoP
     * challenge (RFC 9449 §5.1).
     *
     * <p>{@code ExceptionHandlerAdvice} reads the list from here rather than binding the
     * property a second time, so what a challenge advertises cannot drift from what is
     * enforced. One property, one binding, one list.
     *
     * @return an unmodifiable view, empty rather than null when none are configured
     */
    public List<String> getAllowedAlgorithms() {
        return allowedAlgorithms == null ? List.of() : Collections.unmodifiableList(allowedAlgorithms);
    }

    /** How far in the past a proof's {@code iat} may be. */
    @Value("${mosip.certify.dpop.proof-max-age:60}")
    private long proofMaxAgeSeconds;

    /**
     * Tolerance for clock drift, applied on both sides of the freshness window.
     * Numerically matches eSignet's {@code mosip.esignet.dpop.clock-skew=10}, but note
     * the behaviour differs: eSignet spends its skew on {@code exp}/{@code nbf} only, so
     * a wallet whose clock runs fast passes its token endpoint and is first rejected
     * here. This is the tolerance for device clock offset, not for request latency -
     * that is what {@link #proofMaxAgeSeconds} covers.
     */
    @Value("${mosip.certify.dpop.clock-skew:10}")
    private long maxClockSkewSeconds;

    /**
     * Distributed cache is required when Certify runs multiple replicas: with
     * {@code spring.cache.type=simple} each pod keeps its own map, so a replayed proof
     * simply needs to land on a different pod to slip through. Warned about, not enforced,
     * to match how {@link io.mosip.certify.services.VCICacheService} treats the same risk.
     */
    @Value("${spring.cache.type:simple}")
    private String cacheType;

    /**
     * @param dpopToken         the proof JWT, verbatim from the {@code DPoP} request header
     * @param accessToken       the token from the Authorization header, verbatim
     * @param accessTokenClaims decoded claims of that token, for the {@code cnf.jkt} binding
     * @param request           the inbound request, for {@code htm} / {@code htu}
     * @throws InvalidDpopHeaderException on any failure; returns normally when the proof
     *         satisfies every rule in RFC 9449 section 4.3
     */
    public void validate(String dpopToken, String accessToken,
                                   Map<String, Object> accessTokenClaims, HttpServletRequest request) {
        SignedJWT jwt = parseDpopToken(dpopToken);
        JWK jwk = validateDpopHeader(jwt);
        verifySignature(jwt, jwk);
        JWTClaimsSet claims = getClaims(jwt);
        verifyHtmHtuClaims(claims, request);
        verifyFreshness(claims);
        validateAthClaim(claims, accessToken);

        String jkt = validateCnfClaim(jwk, accessTokenClaims);

        String jti = claims.getJWTID();
        if (jti == null || jti.isBlank()) {
            throw new InvalidDpopHeaderException("DPoP proof is missing the jti claim");
        }
        // Replay check runs last: a proof is only burned once everything else about it has
        // been accepted, so a rejected request cannot consume a valid jti.
        if (checkAndMarkJti(jkt, jti)) {
            log.error("Replay detected for jti: {}", jti);
            throw new InvalidDpopHeaderException("DPoP proof has already been used");
        }
        log.debug("DPoP proof accepted for jkt={}", jkt);
    }

    /**
     * Turns the raw header value into a JWS, checking only that there is exactly one and
     * that it parses.
     *
     * <p>The catch covers the parse alone. Wrapping the header checks in it too would
     * report a rejected {@code typ} or {@code alg} as a malformed JWS, and would convert
     * any {@code IllegalArgumentException} raised by a bug in those checks into a caller
     * error - hiding a fault here behind a message blaming the proof.
     */
    private SignedJWT parseDpopToken(String dpopToken) {
        if (dpopToken == null || dpopToken.isBlank()) {
            throw new InvalidDpopHeaderException("DPoP header is missing");
        }
        // Two proofs folded into one header value by an intermediary. A repeated DPoP
        // header *field* is counted in AccessTokenValidationFilter, which can see the
        // values separately; RFC 9449 §4.3 requires exactly one proof either way.
        if (dpopToken.indexOf(',') >= 0) {
            throw new InvalidDpopHeaderException("Exactly one DPoP proof is allowed");
        }
        try {
            return SignedJWT.parse(dpopToken.trim());
        } catch (ParseException | IllegalArgumentException e) {
            log.error("Failed to parse DPoP JWT", e);
            throw new InvalidDpopHeaderException("DPoP proof is not a well-formed JWS");
        }
    }

    /**
     * Checks the JOSE header of a parsed proof: {@code typ}, {@code alg}, and that it
     * embeds a public key to verify against.
     *
     * @return the embedded public JWK, for the signature check that follows
     */
    private JWK validateDpopHeader(SignedJWT jwt) {
        if (jwt.getHeader().getType() == null
                || !DPOP_JWT_TYPE.equalsIgnoreCase(jwt.getHeader().getType().getType())) {
            log.error("Invalid typ header: expected {}", DPOP_JWT_TYPE);
            throw new InvalidDpopHeaderException("DPoP proof typ header must be " + DPOP_JWT_TYPE);
        }

        String alg = jwt.getHeader().getAlgorithm() == null
                ? null : jwt.getHeader().getAlgorithm().getName();
        if (alg == null || !allowedAlgorithms.contains(alg)) {
            log.error("Invalid or unsupported alg header: {}", alg);
            throw new InvalidDpopHeaderException("Unsupported DPoP proof algorithm: " + alg);
        }

        JWK jwk = jwt.getHeader().getJWK();
        // Nimbus rejects a non-public jwk while parsing the header, so isPrivate()
        // here is belt and braces - reached only if that ever changes.
        if (jwk == null || jwk.isPrivate()) {
            log.error("Invalid jwk header");
            throw new InvalidDpopHeaderException("DPoP proof header must embed a public jwk");
        }
        return jwk;
    }

    private void verifySignature(SignedJWT jwt, JWK jwk) {
        try {
            if (!jwt.verify(createVerifier(jwk))) {
                log.error("DPoP JWT signature verification failed");
                throw new InvalidDpopHeaderException("DPoP proof signature is invalid");
            }
        } catch (JOSEException e) {
            log.error("DPoP signature verification error: {}", e.getMessage());
            throw new InvalidDpopHeaderException("DPoP proof signature could not be verified");
        }
    }

    private JWSVerifier createVerifier(JWK jwk) throws JOSEException {
        switch (jwk.getKeyType().getValue()) {
            case "RSA":
                return new RSASSAVerifier(((RSAKey) jwk).toRSAPublicKey());
            case "EC":
                return new ECDSAVerifier((ECKey) jwk);
            case "OKP":
                // Only the Edwards curves sign; X25519 and X448 are key-agreement keys and
                // can never verify anything, so they are named rather than falling through
                // to the symmetric-key message below, which would misdescribe them.
                OctetKeyPair okp = (OctetKeyPair) jwk;
                if (!Curve.Ed25519.equals(okp.getCurve())) {
                    log.error("Unsupported OKP curve on a DPoP proof: {}", okp.getCurve());
                    throw new InvalidDpopHeaderException(
                            "DPoP proof jwk curve " + okp.getCurve() + " cannot verify a signature");
                }
                return new Ed25519Verifier(okp);
            default:
                log.error("Unsupported JWK key type: {}", jwk.getKeyType());
                throw new InvalidDpopHeaderException("DPoP proof jwk must be an asymmetric key");
        }
    }

    private JWTClaimsSet getClaims(SignedJWT jwt) {
        try {
            return jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            log.error("Failed to get JWT claims");
            throw new InvalidDpopHeaderException("DPoP proof claims are not readable");
        }
    }

    private void verifyHtmHtuClaims(JWTClaimsSet claims, HttpServletRequest request) {
        String htm = getRequiredClaim(claims, HTM);
        if (!request.getMethod().equalsIgnoreCase(htm)) {
            throw new InvalidDpopHeaderException("DPoP proof htm does not match the request method");
        }

        String expected = normalizeConfiguredUri(domainUrl + request.getRequestURI());
        // RFC 9449 §4.3: compare ignoring query and fragment, which normalizeUri drops.
        String htu = normalizeProofHtu(getRequiredClaim(claims, HTU));
        if (!expected.equals(htu)) {
            log.error("DPoP htu mismatch. expected={} received={}", expected, htu);
            throw new InvalidDpopHeaderException("DPoP proof htu does not match the request URI");
        }
    }

    /**
     * Bounds how old a proof may be.
     *
     * <p>eSignet leaves this to Nimbus's {@code DefaultJWTClaimsVerifier}, which requires
     * {@code iat} to be present but range-checks only {@code exp} / {@code nbf} - so a
     * proof without {@code exp} is accepted however old it is. RFC 9449 §11.1 expects the
     * server to bound {@code iat} itself, which is what this does.
     */
    private void verifyFreshness(JWTClaimsSet claims) {
        Date iat = claims.getIssueTime();
        if (iat == null) {
            throw new InvalidDpopHeaderException("DPoP proof is missing the iat claim");
        }
        Instant issuedAt = iat.toInstant();
        Instant now = Instant.now();
        if (issuedAt.isAfter(now.plusSeconds(maxClockSkewSeconds))) {
            throw new InvalidDpopHeaderException("DPoP proof iat is in the future");
        }
        if (issuedAt.isBefore(now.minusSeconds(proofMaxAgeSeconds + maxClockSkewSeconds))) {
            throw new InvalidDpopHeaderException("DPoP proof has expired");
        }
    }

    private void validateAthClaim(JWTClaimsSet claims, String accessToken) {
        String ath = getRequiredClaim(claims, ATH);
        String expected = CommonUtil.generateB64EncodedHash(CommonUtil.ALGO_SHA_256, accessToken);
        if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                ath.getBytes(StandardCharsets.UTF_8))) {
            log.error("ath claim does not match the access token hash");
            throw new InvalidDpopHeaderException("DPoP proof ath does not match the presented access token");
        }
    }

    private String computeThumbprint(JWK publicJwk) {
        try {
            return publicJwk.computeThumbprint().toString();
        } catch (JOSEException e) {
            log.error("Failed to compute DPoP JWK thumbprint", e);
            throw new InvalidDpopHeaderException("DPoP proof jwk thumbprint could not be computed");
        }
    }

    /**
     * The sender-constraining check: the key that signed this proof must be the key the
     * authorization server bound the token to.
     *
     * <p>The thumbprint is computed here rather than by the caller, so the one value the
     * comparison depends on is derived where it is used. It is left until after the
     * {@code cnf} checks: a token with no binding at all is refused without hashing.
     *
     * @return the RFC 7638 thumbprint of the proof key, reused by the caller for the
     *         replay check and returned to the filter
     */
    private String validateCnfClaim(JWK proofJwk, Map<String, Object> accessTokenClaims) {
        Object cnf = accessTokenClaims == null ? null : accessTokenClaims.get(CNF);
        if (!(cnf instanceof Map)) {
            throw new InvalidDpopHeaderException("Access token is not DPoP-bound: cnf claim is missing");
        }
        Object boundJkt = ((Map<?, ?>) cnf).get(JKT);
        if (!(boundJkt instanceof String) || ((String) boundJkt).isBlank()) {
            throw new InvalidDpopHeaderException("Access token is not DPoP-bound: cnf.jkt is missing");
        }
        String jkt = computeThumbprint(proofJwk);
        if (!MessageDigest.isEqual(((String) boundJkt).getBytes(StandardCharsets.UTF_8),
                jkt.getBytes(StandardCharsets.UTF_8))) {
            log.error("cnf claim validation failed");
            throw new InvalidDpopHeaderException("DPoP proof key does not match the access token binding");
        }
        return jkt;
    }

    /**
     * Marks a proof as used, reporting whether it had been used before.
     *
     * <p>Uses {@link Cache#putIfAbsent} rather than get-then-put: the check and the claim
     * are a single atomic operation, so two concurrent replays of the same proof cannot
     * both observe an empty slot and both succeed.
     *
     * <p>The key is scoped to the sender key, not the bare {@code jti}. RFC 9449 only
     * requires {@code jti} to be unique per client, so a global namespace lets one
     * wallet burn a value another wallet may legitimately present later - which would
     * reject a valid proof as a replay.
     *
     * @param jkt RFC 7638 thumbprint of the proof's key, scoping the replay namespace
     * @param jti the proof's unique identifier
     * @return {@code true} if this {@code jti} was already used by this key, i.e. a replay
     * @throws InvalidDpopHeaderException if the cache is not configured
     */
    boolean checkAndMarkJti(String jkt, String jti) {
        Cache cache = cacheManager.getCache(DPOP_JTI_CACHE);
        if (cache == null) {
            // Fail closed. Silently skipping the check would leave every proof replayable
            // while looking perfectly healthy from the outside.
            log.error("Cache {} not available. Please verify cache configuration.", DPOP_JTI_CACHE);
            throw new InvalidDpopHeaderException("DPoP replay cache '" + DPOP_JTI_CACHE
                    + "' is not configured. Add it to mosip.certify.cache.names and "
                    + "mosip.certify.cache.expire-in-seconds.");
        }
        return cache.putIfAbsent(jkt + ":" + jti, System.currentTimeMillis()) != null;
    }

    /**
     * Cache types that share state across replicas, and so give replay protection that
     * actually holds for a multi-pod deployment.
     */
    private static final Set<String> DISTRIBUTED_CACHE_TYPES = Set.of("redis", "hazelcast", "infinispan");

    /** Logged once at startup so a single-pod-only cache setup is visible in the logs. */
    @PostConstruct
    public void warnOnNonDistributedCache() {
        // Allow-list rather than a check for "simple": 'none' disables replay protection
        // outright and 'caffeine' keeps it per-instance, and neither would be reported
        // by a check that only names the default.
        if (cacheType == null || !DISTRIBUTED_CACHE_TYPES.contains(cacheType.toLowerCase(Locale.ROOT))) {
            log.warn("DPoP replay protection is using the '{}' cache, which is not distributed. "
                    + "Replay state is per-instance, so a multi-replica deployment can be defeated by "
                    + "replaying a proof against another replica; with 'none' there is no replay "
                    + "protection at all. Set spring.cache.type=redis for multi-replica deployments.",
                    cacheType);
        }
    }

    private String getRequiredClaim(JWTClaimsSet claims, String name) {
        Object value = claims.getClaim(name);
        if (!(value instanceof String) || ((String) value).isBlank()) {
            throw new InvalidDpopHeaderException("DPoP proof is missing the " + name + " claim");
        }
        return (String) value;
    }

    /**
     * Lowercases scheme and host, drops the default port, query and fragment.
     *
     * <p>Returns {@code null} rather than throwing when the input is not an absolute
     * URI, because the same normalization runs over two inputs with opposite blame:
     * the wallet's {@code htu} claim and this deployment's own configured base. The
     * callers below attach the exception, so a malformed property is never reported
     * as a malformed proof.
     *
     * @return the normalized form, or {@code null} if {@code raw} has no scheme or host
     * @throws URISyntaxException if {@code raw} does not parse as a URI at all
     */
    private String normalizeUri(String raw) throws URISyntaxException {
        URI uri = new URI(raw.trim());
        String scheme = uri.getScheme();
        String host = uri.getHost();
        if (scheme == null || host == null) {
            return null;
        }
        scheme = scheme.toLowerCase(Locale.ROOT);
        host = host.toLowerCase(Locale.ROOT);
        int port = uri.getPort();
        if (("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443)) {
            port = -1;
        }
        // The path is compared verbatim. RFC 9449 §4.3 allows dropping query and fragment
        // and the normalizations of RFC 3986 §6.2.2-6.2.3; trailing-slash removal is in
        // neither, and /credential and /credential/ are distinct resources. Trimming here
        // would let a proof bound to one match a request for the other.
        String path = uri.getRawPath() == null ? "" : uri.getRawPath();
        return scheme + "://" + host + (port == -1 ? "" : ":" + port) + path;
    }

    /** The wallet's {@code htu} claim. A failure here is the caller's to fix. */
    private String normalizeProofHtu(String raw) {
        try {
            String normalized = normalizeUri(raw);
            if (normalized == null) {
                throw new InvalidDpopHeaderException("DPoP proof htu is not an absolute URI");
            }
            return normalized;
        } catch (URISyntaxException e) {
            throw new InvalidDpopHeaderException("DPoP proof htu is not a valid URI");
        }
    }

    /**
     * The URI this deployment expects, built from {@code mosip.certify.domain.url}.
     *
     * <p>A failure here is a misconfiguration of this service, never the caller's, so it
     * must not answer {@code invalid_dpop_proof}: that tells every wallet its proof is
     * malformed when the property is at fault, and no client-side change could fix it.
     * The offending value is logged for the operator and kept out of the response.
     *
     * <p>A value with no scheme is the usual cause - {@code certify-nginx:80} parses as
     * scheme {@code certify-nginx} with a null host, so it fails here rather than at
     * startup, and only on DPoP requests.
     */
    private String normalizeConfiguredUri(String raw) {
        String normalized;
        try {
            normalized = normalizeUri(raw);
        } catch (URISyntaxException e) {
            log.error("mosip.certify.domain.url does not parse as a URI: {}", raw, e);
            throw new IllegalStateException("Cannot resolve the expected DPoP htu: certify's domain URL is misconfigured");
        }
        if (normalized == null) {
            log.error("mosip.certify.domain.url is not an absolute http(s) URI: {}", raw);
            throw new IllegalStateException("Cannot resolve the expected DPoP htu: certify's domain URL is misconfigured");
        }
        return normalized;
    }
}
