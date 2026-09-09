/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.filter;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidDpopHeaderException;
import io.mosip.certify.dpop.DpopProofValidator;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.util.CommonUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Component
@Profile("!local")
public class AccessTokenValidationFilter extends OncePerRequestFilter {

    static final String ERROR_INVALID_TOKEN = "The access token is invalid.";
    static final String ERROR_EXPIRED_TOKEN = "The access token has expired.";
    static final String INVALID_TOKEN_TYPE = "Authorization header with a Bearer or DPoP token is required.";
    static final String ERROR_MISSING_DPOP_PROOF = "A DPoP header is required when using the DPoP authorization scheme.";
    static final String ERROR_TOKEN_REQUIRES_DPOP = "This access token is DPoP-bound and cannot be presented as a Bearer token.";
    static final String ERROR_MULTIPLE_DPOP_PROOFS = "Exactly one DPoP header is allowed.";

    private static final String BEARER_PREFIX = Constants.SCHEME_BEARER + " ";
    private static final String DPOP_PREFIX = Constants.SCHEME_DPOP + " ";

    private static final String CNF = "cnf";
    private static final String JKT = "jkt";

    @Value("${mosip.certify.authn.issuer-uri}")
    private String issuerUri;

    @Value("${mosip.certify.authn.jwk-set-uri}")
    private String jwkSetUri;

    @Value("#{${mosip.certify.authn.allowed-audiences}}")
    private List<String> allowedAudiences;

    @Value("#{${mosip.certify.authn.filter-urls}}")
    private List<String> urlPatterns;

    @Autowired
    private ParsedAccessToken parsedAccessToken;

    @Autowired
    private DpopProofValidator dpopProofValidator;

    private NimbusJwtDecoder nimbusJwtDecoder;

    private boolean isJwt(String token) {
        return token.split("\\.").length == 3;
    }

    private NimbusJwtDecoder getNimbusJwtDecoder() {
        if(nimbusJwtDecoder == null) {
            nimbusJwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).jwsAlgorithms((algo) -> {
                algo.add(SignatureAlgorithm.ES256);
                algo.add(SignatureAlgorithm.RS256);
                algo.add(SignatureAlgorithm.PS256);
            }).build();
            nimbusJwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                    new JwtTimestampValidator(),
                    new JwtIssuerValidator(issuerUri),
                    new JwtClaimValidator<List<String>>(JwtClaimNames.AUD,
                            aud -> aud.stream().anyMatch(allowedAudiences::contains)),
                    new JwtClaimValidator<String>(JwtClaimNames.SUB, Objects::nonNull),
                    new JwtClaimValidator<String>(Constants.CLIENT_ID, Objects::nonNull),
                    new JwtClaimValidator<Instant>(JwtClaimNames.IAT,
                            iat -> iat != null && iat.isBefore(Instant.now(Clock.systemUTC()))),
                    new JwtClaimValidator<Instant>(JwtClaimNames.EXP,
                            exp -> exp != null && exp.isAfter(Instant.now(Clock.systemUTC())))));
        }
        return nimbusJwtDecoder;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        final String path = request.getRequestURI();
        return !urlPatterns.contains(path);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader("Authorization");
        String scheme = resolveScheme(authorizationHeader);

        if (scheme == null) {
            request.setAttribute(Constants.AUTH_ERROR_ATTRIBUTE, INVALID_TOKEN_TYPE);
        } else {
            // Recorded even on the failure paths below, so the 401 answers in the scheme
            // the caller actually used rather than always challenging with Bearer.
            request.setAttribute(Constants.AUTH_SCHEME_ATTRIBUTE, scheme);
            // One line per credential request, naming which scheme the caller used, so a
            // deployment can see whether callers are on Bearer or DPoP without a debug build.
            log.info("Access token presented with the {} authorization scheme", scheme);
            String token = authorizationHeader.substring(scheme.length() + 1);

            //validate access token no matter if its JWT or Opaque
            if (isJwt(token)) {
                try {
                    //Verifies signature and claim predicates, If invalid throws exception
                    Jwt jwt = getNimbusJwtDecoder().decode(token);
                    enforceSchemeBinding(scheme, token, jwt, request);

                    parsedAccessToken.setClaims(new HashMap<>());
                    parsedAccessToken.getClaims().putAll(jwt.getClaims());
                    parsedAccessToken.setAccessTokenHash(CommonUtil.generateOIDCAtHash(token));
                    parsedAccessToken.setActive(true);
                    filterChain.doFilter(request, response);
                    return;

                } catch (CertifyException e) {
                    // DPoP failures already carry a precise, caller-safe description.
                    // The code travels with it so the handler advice can answer
                    // invalid_dpop_proof rather than a generic invalid_token.
                    log.error("DPoP validation failed: {}", e.getMessage());
                    request.setAttribute(Constants.AUTH_ERROR_ATTRIBUTE, e.getMessage());
                    request.setAttribute(Constants.AUTH_ERROR_CODE_ATTRIBUTE, e.getErrorCode());
                } catch (Exception e) {
                    log.error("Access token validation failed", e);
                    request.setAttribute(Constants.AUTH_ERROR_ATTRIBUTE, resolveJwtErrorDescription(e));
                }
            } else {
                request.setAttribute(Constants.AUTH_ERROR_ATTRIBUTE, ERROR_INVALID_TOKEN);
            }
        }

        if (scheme == null) {
            log.error("No Bearer or DPoP authorization header provided, continue with the request chain");
        } else {
            log.error("No valid {} token provided, continue with the request chain", scheme);
        }
        parsedAccessToken.setActive(false);
        filterChain.doFilter(request, response);
    }

    /**
     * Resolves the authorization scheme to its canonical spelling.
     *
     * <p>The comparison ignores case: RFC 9110 §11.1 defines auth-scheme as a case-
     * insensitive token, and RFC 9449 §7.1 says the same of {@code DPoP}. A client
     * sending {@code bearer} or {@code dpop} is conformant, and matching exactly would
     * answer it 401 with "Authorization header with a Bearer or DPoP token is required",
     * which points at the wrong thing entirely.
     *
     * <p>The canonical constant is returned rather than what arrived, so the length used
     * to strip the prefix in {@code doFilterInternal} stays correct - the scheme name and
     * its constant are the same length whatever the casing - and the challenge is issued
     * in the spelling the RFCs use.
     *
     * @return {@link Constants#SCHEME_BEARER}, {@link Constants#SCHEME_DPOP}, or
     *         {@code null} when the header is absent or carries neither scheme
     */
    private String resolveScheme(String authorizationHeader) {
        if (authorizationHeader == null) {
            return null;
        }
        if (startsWithIgnoreCase(authorizationHeader, BEARER_PREFIX)) {
            return Constants.SCHEME_BEARER;
        }
        if (startsWithIgnoreCase(authorizationHeader, DPOP_PREFIX)) {
            return Constants.SCHEME_DPOP;
        }
        return null;
    }

    private boolean startsWithIgnoreCase(String value, String prefix) {
        return value.regionMatches(true, 0, prefix, 0, prefix.length());
    }

    /**
     * Enforces the rules tying the scheme the caller used to the binding the token carries,
     * once the token itself is known to be valid. Both directions are checked.
     *
     * <p>Under the DPoP scheme a proof is required and must satisfy every rule in
     * {@link DpopProofValidator}. Under Bearer the check is a downgrade guard: a token
     * carrying {@code cnf.jkt} was issued sender-constrained, and accepting it as a plain
     * Bearer token would discard exactly the protection DPoP exists to provide - a stolen
     * token would work again.
     */
    private void enforceSchemeBinding(String scheme, String token, Jwt jwt, HttpServletRequest request) {
        if (Constants.SCHEME_DPOP.equals(scheme)) {
            // Read through getHeaders, not getHeader: the latter answers with the first
            // value alone, so a request carrying two DPoP header fields would be validated
            // against the first and the second never looked at. RFC 9449 §4.3 requires the
            // resource server to reject that, and counting is only possible here - the
            // validator is handed one string and cannot tell how many arrived.
            Enumeration<String> dpopHeaders = request.getHeaders(Constants.DPOP);
            String dpopToken = (dpopHeaders != null && dpopHeaders.hasMoreElements())
                    ? dpopHeaders.nextElement() : null;
            if (dpopToken == null || dpopToken.isBlank()) {
                throw new InvalidDpopHeaderException(ERROR_MISSING_DPOP_PROOF);
            }
            if (dpopHeaders.hasMoreElements()) {
                throw new InvalidDpopHeaderException(ERROR_MULTIPLE_DPOP_PROOFS);
            }
            // Everything the proof has to satisfy - structure, signature, request and token
            // binding, freshness, single use - is decided in there.
            dpopProofValidator.validate(dpopToken, token, jwt.getClaims(), request);

        } else if (isDpopBoundAccessToken(jwt.getClaims())) {
            throw new InvalidDpopHeaderException(ERROR_TOKEN_REQUIRES_DPOP);
        }
    }

    private boolean isDpopBoundAccessToken(Map<String, Object> claims) {
        Object cnf = claims.get(CNF);
        return cnf instanceof Map && ((Map<?, ?>) cnf).get(JKT) != null;
    }

    private String resolveJwtErrorDescription(Exception e) {
        if (e instanceof JwtValidationException) {
            boolean expired = ((JwtValidationException) e).getErrors().stream()
                    .map(OAuth2Error::getDescription)
                    .filter(Objects::nonNull)
                    .anyMatch(description -> description.toLowerCase().contains("expired"));
            if (expired) {
                return ERROR_EXPIRED_TOKEN;
            }
        }
        return ERROR_INVALID_TOKEN;
    }
}
