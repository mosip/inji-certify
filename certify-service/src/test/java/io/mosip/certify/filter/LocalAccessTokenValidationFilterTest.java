package io.mosip.certify.filter;

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
import org.springframework.test.util.ReflectionTestUtils;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import java.io.IOException;
import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

class LocalAccessTokenValidationFilterTest {

    @InjectMocks
    private LocalAccessTokenValidationFilter filter;

    @Mock
    private ParsedAccessToken parsedAccessToken;

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
    public void whenValidTestBearerToken_shouldProcessSuccessfully() throws ServletException, IOException {
        request.addHeader("Authorization", "TestBearer " + TOKEN);

        filter.doFilterInternal(request, response, filterChain);

        verify(parsedAccessToken).setClaims(any());
        verify(parsedAccessToken).setActive(true);
        verify(parsedAccessToken).setAccessTokenHash(any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    public void whenNoAuthHeader_shouldCreateDefaultToken() throws ServletException, IOException {
        // No Authorization header
        filter.doFilterInternal(request, response, filterChain);

        verify(parsedAccessToken).setClaims(any());
        verify(parsedAccessToken).setActive(true);
        verify(parsedAccessToken).setAccessTokenHash(any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    public void whenNonTestBearerToken_shouldCreateDefaultToken() throws ServletException, IOException {
        request.addHeader("Authorization", "Bearer " + TOKEN);

        filter.doFilterInternal(request, response, filterChain);

        verify(parsedAccessToken).setClaims(any());
        verify(parsedAccessToken).setActive(true);
        verify(parsedAccessToken).setAccessTokenHash(any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    public void whenMalformedTestBearerToken_shouldHandleException() throws ServletException, IOException {
        request.addHeader("Authorization", "TestBearer malformed");

        filter.doFilterInternal(request, response, filterChain);

        verify(parsedAccessToken).setClaims(any());
        verify(parsedAccessToken).setActive(true);
        verify(parsedAccessToken).setAccessTokenHash(any());
        verify(filterChain).doFilter(request, response);
    }
}