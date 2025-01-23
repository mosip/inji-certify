package io.mosip.certify.filter;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.util.CommonUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.util.ReflectionTestUtils;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

class AccessTokenValidationFilterTest {

    @InjectMocks
    private AccessTokenValidationFilter filter;

    @Mock
    private ParsedAccessToken parsedAccessToken;

    @Mock
    private NimbusJwtDecoder jwtDecoder;

    @Mock
    private FilterChain filterChain;

    @Mock
    private CommonUtil commonUtil;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private static final String TOKEN = "header.payload.signature";
    private static final String TEST_ISSUER = "https://test-issuer.com";
    private static final String TEST_JWK_SET = "https://test-issuer.com/.well-known/jwks.json";

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();

        ReflectionTestUtils.setField(filter, "issuerUri", TEST_ISSUER);
        ReflectionTestUtils.setField(filter, "jwkSetUri", TEST_JWK_SET);
        ReflectionTestUtils.setField(filter, "allowedAudiences", Arrays.asList("test-client"));
        ReflectionTestUtils.setField(filter, "urlPatterns", Arrays.asList("/api/v1/test", "/api/v1/secured"));
        ReflectionTestUtils.setField(filter, "nimbusJwtDecoder", jwtDecoder);
    }

    @Test
    public void whenNimbusJwtDecoderNull_shouldCreateNewInstance() {
        ReflectionTestUtils.setField(filter, "nimbusJwtDecoder", null);
        request.addHeader("Authorization", "Bearer " + TOKEN);

        Jwt jwt = mock(Jwt.class);
        when(jwt.getClaims()).thenReturn(createValidClaims());
        when(jwtDecoder.decode(anyString())).thenReturn(jwt);

        assertDoesNotThrow(() -> filter.doFilterInternal(request, response, filterChain));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/api/v1/test", "/api/v1/secured"})
    public void shouldFilterForConfiguredUrls(String url) throws ServletException {
        request.setRequestURI(url);
        assertFalse(filter.shouldNotFilter(request));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/api/v1/public", "/health", "/random"})
    public void shouldNotFilterForNonConfiguredUrls(String url) throws ServletException {
        request.setRequestURI(url);
        assertTrue(filter.shouldNotFilter(request));
    }

    @Test
    public void whenValidJwtTokenWithAllClaims_shouldProcessSuccessfully() throws ServletException, IOException {
        request.addHeader("Authorization", "Bearer " + TOKEN);

        Jwt jwt = mock(Jwt.class);
        Map<String, Object> claims = createValidClaims();
        when(jwt.getClaims()).thenReturn(claims);
        when(jwtDecoder.decode(TOKEN)).thenReturn(jwt);

        filter.doFilterInternal(request, response, filterChain);

        verify(parsedAccessToken).setClaims(any());
        verify(parsedAccessToken).setActive(true);
        verify(parsedAccessToken).setAccessTokenHash(any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    public void whenTokenWithMissingClaims_shouldHandleValidationFailure() throws ServletException, IOException {
        request.addHeader("Authorization", "Bearer " + TOKEN);

        when(jwtDecoder.decode(TOKEN)).thenThrow(
                new JwtValidationException("Missing claims",
                        Arrays.asList(new OAuth2Error("invalid_token", "Required claim 'sub' is missing", null)))
        );

        filter.doFilterInternal(request, response, filterChain);

        verify(parsedAccessToken).setActive(false);
        verify(filterChain).doFilter(request, response);
    }

    @Test
    public void whenTokenWithExpiredTimestamp_shouldHandleValidationFailure() throws ServletException, IOException {
        request.addHeader("Authorization", "Bearer " + TOKEN);

        when(jwtDecoder.decode(TOKEN)).thenThrow(
                new JwtValidationException("Token expired",
                        Arrays.asList(new OAuth2Error("invalid_token", "Jwt expired at...", null)))
        );

        filter.doFilterInternal(request, response, filterChain);

        verify(parsedAccessToken).setActive(false);
        verify(filterChain).doFilter(request, response);
    }

    @Test
    public void whenTokenWithInvalidSignature_shouldHandleValidationFailure() throws ServletException, IOException {
        request.addHeader("Authorization", "Bearer " + TOKEN);

        when(jwtDecoder.decode(TOKEN)).thenThrow(
                new JwtValidationException("Invalid signature",
                        Arrays.asList(new OAuth2Error("invalid_token", "Jwt signature invalid", null)))
        );

        filter.doFilterInternal(request, response, filterChain);

        verify(parsedAccessToken).setActive(false);
        verify(filterChain).doFilter(request, response);
    }

    @Test
    public void whenMalformedJwt_shouldHandleException() throws ServletException, IOException {
        request.addHeader("Authorization", "Bearer malformed.jwt");

        when(jwtDecoder.decode(anyString())).thenThrow(new BadJwtException("Malformed JWT"));

        filter.doFilterInternal(request, response, filterChain);

        verify(parsedAccessToken).setActive(false);
        verify(filterChain).doFilter(request, response);
    }

    @Test
    public void whenNullAuthorizationHeader_shouldHandleGracefully() throws ServletException, IOException {
        filter.doFilterInternal(request, response, filterChain);

        verify(parsedAccessToken).setActive(false);
        verify(filterChain).doFilter(request, response);
    }

    private Map<String, Object> createValidClaims() {
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtClaimNames.SUB, "test-subject");
        claims.put(JwtClaimNames.AUD, Arrays.asList("test-client"));
        claims.put(Constants.CLIENT_ID, "test-client");
        claims.put(JwtClaimNames.ISS, TEST_ISSUER);
        claims.put(JwtClaimNames.IAT, Instant.now().minusSeconds(60));
        claims.put(JwtClaimNames.EXP, Instant.now().plusSeconds(300));
        return claims;
    }
}