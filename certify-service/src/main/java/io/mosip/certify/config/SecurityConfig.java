/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.config;

import io.mosip.certify.core.config.LocalAuthenticationEntryPoint;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;


import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Slf4j
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@Profile(value = {"!test"})
public class SecurityConfig {

    @Autowired
    private LocalAuthenticationEntryPoint localAuthenticationEntryPoint;

    @Value("${server.servlet.path}")
    private String servletPath;

    @Value("#{${mosip.certify.security.auth.post-urls}}")
    private Map<String, List<String>> securePostUrls;

    @Value("#{${mosip.certify.security.auth.put-urls}}")
    private Map<String, List<String>> securePutUrls;

    @Value("#{${mosip.certify.security.auth.get-urls}}")
    private Map<String, List<String>> secureGetUrls;

    @Value("${mosip.certify.authn.jwk-set-uri}")
    private String jwkSetUri;

    @Value("${mosip.certify.security.ignore-auth-urls}")
    private String[] ignoreAuthUrls;

    @Value("${mosip.certify.security.ignore-csrf-urls}")
    private String[] ignoreCsrfCheckUrls;

    @Value("${mosip.certify.security.cors-enabled-get-method-urls:}")
    private String corsEnabledGetMethodUrls;

    @Bean
    public SecurityFilterChain web(HttpSecurity http) throws Exception {

        http.csrf(httpEntry -> httpEntry.ignoringRequestMatchers(ignoreCsrfCheckUrls)
                .csrfTokenRepository(this.getCsrfTokenRepository()));

        http.cors(Customizer.withDefaults());

        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests
                .requestMatchers(ignoreAuthUrls).permitAll()
                .anyRequest().authenticated()
        ).oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                        .jwkSetUri(jwkSetUri)
                )
        );
        http.exceptionHandling(exceptionConfigurer -> exceptionConfigurer.authenticationEntryPoint(localAuthenticationEntryPoint));
        http.sessionManagement(sessionConfigurer -> sessionConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }

    private CsrfTokenRepository getCsrfTokenRepository() {
        CookieCsrfTokenRepository cookieCsrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        cookieCsrfTokenRepository.setCookiePath("/");
        return cookieCsrfTokenRepository;
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        CorsConfiguration publicPathConfig = new CorsConfiguration();

        // Allow all origins (*)
        publicPathConfig.setAllowedOrigins(Collections.singletonList("*"));

        // Allow ONLY GET requests (and the mandatory OPTIONS pre-flight request)
        publicPathConfig.setAllowedMethods(Arrays.asList(HttpMethod.GET.name(), HttpMethod.OPTIONS.name()));

        // Allows all headers
        publicPathConfig.setAllowedHeaders(Collections.singletonList("*"));

        // Credentials set to false as we are allowing all origins
        publicPathConfig.setAllowCredentials(false);

        // Register this configuration only for the urls enabled for CORS
        if(!corsEnabledGetMethodUrls.trim().isEmpty()) {
            for (String pattern : corsEnabledGetMethodUrls.split(",")) {
                String trimmedPattern = pattern.trim();
                if(!trimmedPattern.isEmpty()) {
                    source.registerCorsConfiguration(trimmedPattern, publicPathConfig);
                }
            }
        }

        return source;
    }

}
