package io.mosip.certify.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.ProblemDetailsTypes;
import io.mosip.certify.core.dto.ProblemDetails;
import io.mosip.certify.core.util.ProblemDetailsBuilder;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
@Component
@ConditionalOnProperty(value = "mosip.certify.vc-api.enabled", havingValue = "true")
public class VCApiKeyAuthFilter extends OncePerRequestFilter {

    public static final String API_KEY_HEADER = "X-API-Key";

    @Value("${server.servlet.path}")
    private String servletPath;

    @Value("${mosip.certify.vc-api.api-keys:}")
    private String apiKeysConfig;

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith(servletPath + "/vc-api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String apiKey = request.getHeader(API_KEY_HEADER);
        if (StringUtils.isBlank(apiKey) || !getConfiguredApiKeys().contains(apiKey.trim())) {
            log.warn("VC API request rejected: missing or invalid API key");
            writeUnauthorizedProblem(request, response);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                "vc-api-client",
                null,
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_VC_API")));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        try {
            filterChain.doFilter(request, response);
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    private Set<String> getConfiguredApiKeys() {
        if (StringUtils.isBlank(apiKeysConfig)) {
            return Collections.emptySet();
        }
        return Stream.of(apiKeysConfig.split(","))
                .map(String::trim)
                .filter(StringUtils::isNotBlank)
                .collect(Collectors.toSet());
    }

    private void writeUnauthorizedProblem(HttpServletRequest request, HttpServletResponse response) throws IOException {
        ProblemDetails body = ProblemDetailsBuilder.create(
                HttpStatus.UNAUTHORIZED,
                ProblemDetailsTypes.ABOUT_BLANK,
                "Invalid or missing API key",
                request.getRequestURI());
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        objectMapper.writeValue(response.getWriter(), body);
    }
}
