package io.mosip.certify.filter;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.ParsedAccessToken;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AccessTokenValidationFilterTest {

    @InjectMocks
    private AccessTokenValidationFilter filter;

    private ParsedAccessToken parsedAccessToken;

    @Mock
    private NimbusJwtDecoder jwtDecoder;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        ReflectionTestUtils.setField(filter, "jwkSetUri", "https://mock-jwk-uri");
        ReflectionTestUtils.setField(filter, "issuerUri", "https://mock-issuer-uri");
        ReflectionTestUtils.setField(filter, "allowedAudiences", List.of("mock-audience"));
        ReflectionTestUtils.setField(filter, "urlPatterns", List.of("/api/protected"));
        parsedAccessToken = new ParsedAccessToken();
        ReflectionTestUtils.setField(filter, "parsedAccessToken", parsedAccessToken);
    }

    @Test
    void testShouldNotFilter() throws ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/public");
        assertTrue(filter.shouldNotFilter(request));
    }

    @Test
    void testShouldFilter() throws ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/protected");
        assertFalse(filter.shouldNotFilter(request));
    }

    @Test
    void testDoFilter_ValidJwt() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer valid.jwt.token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        Jwt jwt = Jwt.withTokenValue("valid.jwt.token")
                .header("alg", "RS256")
                .claim(Constants.CLIENT_ID, "client123")
                .claim("sub", "subject")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .build();

        when(jwtDecoder.decode(anyString())).thenReturn(jwt);
        ReflectionTestUtils.setField(filter, "nimbusJwtDecoder", jwtDecoder);
        filter.doFilterInternal(request, response, filterChain);
        assertTrue(parsedAccessToken.isActive());
        assertEquals("client123", parsedAccessToken.getClaims().get(Constants.CLIENT_ID));
    }

    @Test
    void testDoFilter_InvalidJwt() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer invalid.jwt.token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        when(jwtDecoder.decode(anyString())).thenThrow(new JwtException("Invalid Token"));
        ReflectionTestUtils.setField(filter, "nimbusJwtDecoder", jwtDecoder);
        filter.doFilterInternal(request, response, filterChain);
        assertFalse(parsedAccessToken.isActive());
    }

    @Test
    void testDoFilter_WithoutAuthorizationHeader() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        filter.doFilterInternal(request, response, filterChain);
        assertFalse(parsedAccessToken.isActive());
    }
}
