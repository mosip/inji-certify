/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.vci.filter;

import io.mosip.certify.core.dto.vci.ParsedAccessToken;
import io.mosip.certify.core.util.IdentityProviderUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

import static io.mosip.certify.core.spi.TokenService.CLIENT_ID;

@Slf4j
@Component
public class AccessTokenValidationFilter extends OncePerRequestFilter {

    @Value("${mosip.esignet.vci.authn.issuer-uri}")
    private String issuerUri;

    @Value("${mosip.esignet.vci.authn.jwk-set-uri}")
    private String jwkSetUri;

    @Value("#{${mosip.esignet.vci.authn.allowed-audiences}}")
    private List<String> allowedAudiences;

    @Value("#{${mosip.esignet.vci.authn.filter-urls}}")
    private List<String> urlPatterns;

    @Autowired
    private ParsedAccessToken parsedAccessToken;

    private NimbusJwtDecoder nimbusJwtDecoder;


    private boolean isJwt(String token) {
        return token.split("\\.").length == 3;
    }

    private NimbusJwtDecoder getNimbusJwtDecoder() {
        if(nimbusJwtDecoder == null) {
            nimbusJwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
            nimbusJwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                    new JwtTimestampValidator(),
                    new JwtIssuerValidator(issuerUri),
                    new JwtClaimValidator<List<String>>(JwtClaimNames.AUD, allowedAudiences::containsAll),
                    new JwtClaimValidator<String>(JwtClaimNames.SUB, Objects::nonNull),
                    new JwtClaimValidator<String>(CLIENT_ID, Objects::nonNull),
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

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7);
            //validate access token no matter if its JWT or Opaque
            if(isJwt(token)) {
                try {
                    //Verifies signature and claim predicates, If invalid throws exception
                    Jwt jwt = getNimbusJwtDecoder().decode(token);
                    parsedAccessToken.setClaims(new HashMap<>());
                    parsedAccessToken.getClaims().putAll(jwt.getClaims());
                    parsedAccessToken.setAccessTokenHash(IdentityProviderUtil.generateOIDCAtHash(token));
                    parsedAccessToken.setActive(true);
                    filterChain.doFilter(request, response);
                    return;

                } catch (Exception e) {
                    log.error("Access token validation failed", e);
                }
            }
        }

        log.error("No Bearer / Opaque token provided, continue with the request chain");
        parsedAccessToken.setActive(false);
        filterChain.doFilter(request, response);
    }
}
