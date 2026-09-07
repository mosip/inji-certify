package io.mosip.certify.config;

import io.mosip.certify.filter.VCApiKeyAuthFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@ConditionalOnProperty(value = "mosip.certify.vc-api.enabled", havingValue = "true")
public class VCApiSecurityConfig {

    @Value("${server.servlet.path}")
    private String servletPath;

    @Autowired
    private VCApiKeyAuthFilter vcApiKeyAuthFilter;

    @Bean
    @Order(1)
    public SecurityFilterChain vcApiSecurityFilterChain(HttpSecurity http) throws Exception {
        String vcApiPattern = servletPath + "/vc-api/**";
        http.securityMatcher(vcApiPattern)
                // Stateless X-API-Key auth (no cookies/sessions); ignore CSRF for this API only.
                .csrf(csrf -> csrf.ignoringRequestMatchers(vcApiPattern))
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .addFilterBefore(vcApiKeyAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }
}
