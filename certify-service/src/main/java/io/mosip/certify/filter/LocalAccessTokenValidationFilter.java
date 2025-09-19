/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.filter;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.util.CommonUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Component
@Profile("local")
public class LocalAccessTokenValidationFilter extends OncePerRequestFilter {

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

    private NimbusJwtDecoder nimbusJwtDecoder;


    private boolean isJwt(String token) {
        return token.split("\\.").length == 3;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        final String path = request.getRequestURI();
        return !urlPatterns.contains(path);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader("Authorization");
        log.warn("Local Validator Enabled. THIS IS A DEBUG ONLY FEATURE, DO NOT TURN ON IN PRODUCTION");
        log.info("Use TestBearer token to pass your own claims in unsecurted JWT format");
        if (authorizationHeader != null && authorizationHeader.startsWith("TestBearer ")) {
            String token = authorizationHeader.substring(11);
            //validate access token no matter if its JWT or Opaque
            if(isJwt(token)) {
                try {
                    
                    Jwt jwt = Jwt.withTokenValue(token).build();  //getNimbusJwtDecoder().decode(token); 
                    parsedAccessToken.setClaims(new HashMap<>());
                    parsedAccessToken.getClaims().putAll(jwt.getClaims());
                    parsedAccessToken.setAccessTokenHash(CommonUtil.generateOIDCAtHash(token));
                    parsedAccessToken.setActive(true);
                    filterChain.doFilter(request, response);
                    return;

                } catch (Exception e) {
                    log.error("Access token validation failed", e);
                }
            }
        }
        
        parsedAccessToken.setClaims(new HashMap<>());
        parsedAccessToken.getClaims().put("iat", Instant.now().getEpochSecond());
        parsedAccessToken.getClaims().put("nbf", Instant.now().getEpochSecond());
        parsedAccessToken.getClaims().put("exp", Instant.now().plusSeconds(TimeUnit.MINUTES.toSeconds( 10 )).getEpochSecond());
        parsedAccessToken.getClaims().put("jti", "WTHVMJHxEHSe_zRYcfvJF");
        parsedAccessToken.getClaims().put("aud", "https://local.mock.esignet.io");
        parsedAccessToken.getClaims().put("c_nonce", "nZEA28AFIrUsYD8o5vDG");
        parsedAccessToken.getClaims().put("iss", "demo-local-certify");
        parsedAccessToken.getClaims().put("sub", "user@inji.io");
        parsedAccessToken.getClaims().put("client_id", "demo-certify");
        parsedAccessToken.getClaims().put("scope", "sample_vc_ldp");
        parsedAccessToken.getClaims().put("c_nonce_expires_in", 86400);
        parsedAccessToken.setAccessTokenHash(CommonUtil.generateOIDCAtHash("demo"));
        parsedAccessToken.setActive(true);
        log.debug("No Bearer / Opaque token provided, continue with the fake token" , parsedAccessToken.toString() );
        filterChain.doFilter(request, response);
    }
}
