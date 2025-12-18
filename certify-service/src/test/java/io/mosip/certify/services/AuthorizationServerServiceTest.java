package io.mosip.certify.services;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.AuthorizationServerConfig;
import io.mosip.certify.core.dto.AuthorizationServerMetadata;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class AuthorizationServerServiceTest {

    @Mock
    private VCICacheService vciCacheService;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private RestTemplate restTemplate;

    @InjectMocks
    private AuthorizationServerService authorizationServerService;

    private static final String INTERNAL_SERVER_URL = "https://internal-auth.example.com";
    private static final String EXTERNAL_SERVER_URL = "https://external-auth.example.com";
    private static final String DEFAULT_SERVER_URL = "https://default-auth.example.com";

    @Before
    public void setup() {
        ReflectionTestUtils.setField(authorizationServerService, "retryCount", 3);
        ReflectionTestUtils.setField(authorizationServerService, "internalAuthServerUrl", INTERNAL_SERVER_URL);
        ReflectionTestUtils.setField(authorizationServerService, "authorizationServersConfig", "");
        ReflectionTestUtils.setField(authorizationServerService, "defaultAuthServer", "");
        ReflectionTestUtils.setField(authorizationServerService, "credentialConfigMappingJson", "{}");
    }

    // ========== Tests for initialize() and loadConfiguredServers() ==========

    @Test
    public void initialize_WithInternalServerOnly_Success() {
        authorizationServerService.initialize();

        List<String> urls = authorizationServerService.getAllAuthorizationServerUrls();
        assertEquals(1, urls.size());
        assertEquals(INTERNAL_SERVER_URL, urls.get(0));
    }

    @Test
    public void initialize_WithExternalServers_Success() {
        ReflectionTestUtils.setField(authorizationServerService, "authorizationServersConfig",
                "https://auth1.example.com, https://auth2.example.com");

        authorizationServerService.initialize();

        List<String> urls = authorizationServerService.getAllAuthorizationServerUrls();
        assertEquals(3, urls.size()); // internal + 2 external
    }

    @Test
    public void initialize_WithNoServers_NoException() {
        ReflectionTestUtils.setField(authorizationServerService, "internalAuthServerUrl", "");
        ReflectionTestUtils.setField(authorizationServerService, "authorizationServersConfig", "");

        authorizationServerService.initialize();

        List<String> urls = authorizationServerService.getAllAuthorizationServerUrls();
        assertEquals(0, urls.size());
    }

    @Test
    public void initialize_WithEmptyExternalConfig_OnlyInternalAdded() {
        ReflectionTestUtils.setField(authorizationServerService, "authorizationServersConfig", "  ,  ");

        authorizationServerService.initialize();

        List<String> urls = authorizationServerService.getAllAuthorizationServerUrls();
        assertEquals(1, urls.size());
        assertEquals(INTERNAL_SERVER_URL, urls.get(0));
    }

    // ========== Tests for loadCredentialConfigMappings() ==========

    @Test
    public void initialize_WithCredentialConfigMappings_Success() throws Exception {
        String mappingJson = "{\"config1\":\"https://auth1.example.com\",\"config2\":\"https://auth2.example.com\"}";
        ReflectionTestUtils.setField(authorizationServerService, "credentialConfigMappingJson", mappingJson);

        when(objectMapper.readValue(eq(mappingJson), any(TypeReference.class)))
                .thenReturn(Map.of("config1", "https://auth1.example.com", "config2", "https://auth2.example.com"));

        authorizationServerService.initialize();

        verify(objectMapper).readValue(eq(mappingJson), any(TypeReference.class));
    }

    @Test
    public void initialize_WithInvalidCredentialConfigMappings_NoException() throws Exception {
        String mappingJson = "invalid-json";
        ReflectionTestUtils.setField(authorizationServerService, "credentialConfigMappingJson", mappingJson);

        when(objectMapper.readValue(eq(mappingJson), any(TypeReference.class)))
                .thenThrow(new RuntimeException("Invalid JSON"));

        // Should not throw, just log error
        authorizationServerService.initialize();
    }

    // ========== Tests for getInternalAuthServerMetadata() ==========

    @Test
    public void getInternalAuthServerMetadata_Success() {
        authorizationServerService.initialize();

        AuthorizationServerMetadata metadata = authorizationServerService.getInternalAuthServerMetadata();

        assertNotNull(metadata);
        assertEquals(INTERNAL_SERVER_URL, metadata.getIssuer());
        assertEquals(INTERNAL_SERVER_URL + "/token", metadata.getTokenEndpoint());
        assertEquals(INTERNAL_SERVER_URL + "/authorize", metadata.getAuthorizationEndpoint());
        assertEquals(INTERNAL_SERVER_URL + "/jwks.json", metadata.getJwksUri());
    }

    @Test
    public void getInternalAuthServerMetadata_NormalizesTrailingSlash() {
        ReflectionTestUtils.setField(authorizationServerService, "internalAuthServerUrl",
                INTERNAL_SERVER_URL + "/");
        authorizationServerService.initialize();

        AuthorizationServerMetadata metadata = authorizationServerService.getInternalAuthServerMetadata();

        assertEquals(INTERNAL_SERVER_URL, metadata.getIssuer());
    }

    // ========== Tests for discoverMetadata() ==========

    @Test
    public void discoverMetadata_CacheHit_ReturnsCachedMetadata() {
        AuthorizationServerMetadata cachedMetadata = AuthorizationServerMetadata.builder()
                .issuer(EXTERNAL_SERVER_URL)
                .tokenEndpoint(EXTERNAL_SERVER_URL + "/token")
                .build();

        when(vciCacheService.getASMetadata(EXTERNAL_SERVER_URL)).thenReturn(cachedMetadata);

        AuthorizationServerMetadata result = authorizationServerService.discoverMetadata(EXTERNAL_SERVER_URL);

        assertEquals(cachedMetadata, result);
        verify(restTemplate, never()).getForEntity(any(URI.class), eq(String.class));
    }

    @Test
    public void discoverMetadata_CacheMiss_DiscoverFromOIDC_Success() throws Exception {
        when(vciCacheService.getASMetadata(EXTERNAL_SERVER_URL)).thenReturn(null);

        String metadataJson = "{\"issuer\":\"" + EXTERNAL_SERVER_URL + "\",\"token_endpoint\":\"" + EXTERNAL_SERVER_URL + "/token\"}";
        ResponseEntity<String> response = new ResponseEntity<>(metadataJson, HttpStatus.OK);

        when(restTemplate.getForEntity(any(URI.class), eq(String.class))).thenReturn(response);

        AuthorizationServerMetadata expectedMetadata = AuthorizationServerMetadata.builder()
                .issuer(EXTERNAL_SERVER_URL)
                .tokenEndpoint(EXTERNAL_SERVER_URL + "/token")
                .build();

        when(objectMapper.readValue(eq(metadataJson), eq(AuthorizationServerMetadata.class)))
                .thenReturn(expectedMetadata);

        AuthorizationServerMetadata result = authorizationServerService.discoverMetadata(EXTERNAL_SERVER_URL);

        assertNotNull(result);
        assertEquals(EXTERNAL_SERVER_URL, result.getIssuer());
        verify(vciCacheService).setASMetadata(eq(EXTERNAL_SERVER_URL), eq(expectedMetadata));
    }

    @Test
    public void discoverMetadata_OIDCFails_FallbackToOAuth_Success() throws Exception {
        when(vciCacheService.getASMetadata(EXTERNAL_SERVER_URL)).thenReturn(null);

        // First call to OIDC endpoint fails
        ResponseEntity<String> failedResponse = new ResponseEntity<>(null, HttpStatus.NOT_FOUND);

        // Second call to OAuth AS endpoint succeeds
        String metadataJson = "{\"issuer\":\"" + EXTERNAL_SERVER_URL + "\",\"token_endpoint\":\"" + EXTERNAL_SERVER_URL + "/token\"}";
        ResponseEntity<String> successResponse = new ResponseEntity<>(metadataJson, HttpStatus.OK);

        when(restTemplate.getForEntity(any(URI.class), eq(String.class)))
                .thenReturn(failedResponse)
                .thenReturn(failedResponse)
                .thenReturn(failedResponse) // 3 retries for OIDC
                .thenReturn(successResponse);

        AuthorizationServerMetadata expectedMetadata = AuthorizationServerMetadata.builder()
                .issuer(EXTERNAL_SERVER_URL)
                .tokenEndpoint(EXTERNAL_SERVER_URL + "/token")
                .build();

        when(objectMapper.readValue(eq(metadataJson), eq(AuthorizationServerMetadata.class)))
                .thenReturn(expectedMetadata);

        AuthorizationServerMetadata result = authorizationServerService.discoverMetadata(EXTERNAL_SERVER_URL);

        assertNotNull(result);
    }

    @Test
    public void discoverMetadata_AllAttemptsFail_ThrowsCertifyException() throws Exception {
        when(vciCacheService.getASMetadata(EXTERNAL_SERVER_URL)).thenReturn(null);

        // All calls fail
        ResponseEntity<String> failedResponse = new ResponseEntity<>(null, HttpStatus.NOT_FOUND);
        when(restTemplate.getForEntity(any(URI.class), eq(String.class))).thenReturn(failedResponse);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> authorizationServerService.discoverMetadata(EXTERNAL_SERVER_URL));

        assertEquals(ErrorConstants.AUTHORIZATION_SERVER_DISCOVERY_FAILED, exception.getErrorCode());
    }

    @Test
    public void discoverMetadata_InvalidMetadata_ThrowsCertifyException() throws Exception {
        when(vciCacheService.getASMetadata(EXTERNAL_SERVER_URL)).thenReturn(null);

        String metadataJson = "{\"issuer\":\"\"}"; // Missing token_endpoint
        ResponseEntity<String> response = new ResponseEntity<>(metadataJson, HttpStatus.OK);

        when(restTemplate.getForEntity(any(URI.class), eq(String.class))).thenReturn(response);

        AuthorizationServerMetadata invalidMetadata = AuthorizationServerMetadata.builder()
                .issuer("")
                .build();

        when(objectMapper.readValue(eq(metadataJson), eq(AuthorizationServerMetadata.class)))
                .thenReturn(invalidMetadata);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> authorizationServerService.discoverMetadata(EXTERNAL_SERVER_URL));

        assertEquals(ErrorConstants.AUTHORIZATION_SERVER_DISCOVERY_FAILED, exception.getErrorCode());
    }

    // ========== Tests for getTokenEndpoint() ==========

    @Test
    public void getTokenEndpoint_Success() {
        AuthorizationServerMetadata metadata = AuthorizationServerMetadata.builder()
                .issuer(EXTERNAL_SERVER_URL)
                .tokenEndpoint(EXTERNAL_SERVER_URL + "/token")
                .build();

        when(vciCacheService.getASMetadata(EXTERNAL_SERVER_URL)).thenReturn(metadata);

        String tokenEndpoint = authorizationServerService.getTokenEndpoint(EXTERNAL_SERVER_URL);

        assertEquals(EXTERNAL_SERVER_URL + "/token", tokenEndpoint);
    }

    // ========== Tests for getJwksUri() ==========

    @Test
    public void getJwksUri_Success() {
        AuthorizationServerMetadata metadata = AuthorizationServerMetadata.builder()
                .issuer(EXTERNAL_SERVER_URL)
                .tokenEndpoint(EXTERNAL_SERVER_URL + "/token")
                .jwksUri(EXTERNAL_SERVER_URL + "/jwks.json")
                .build();

        when(vciCacheService.getASMetadata(EXTERNAL_SERVER_URL)).thenReturn(metadata);

        String jwksUri = authorizationServerService.getJwksUri(EXTERNAL_SERVER_URL);

        assertEquals(EXTERNAL_SERVER_URL + "/jwks.json", jwksUri);
    }

    // ========== Tests for supportsPreAuthorizedCodeGrant() ==========

    @Test
    public void supportsPreAuthorizedCodeGrant_Supported_ReturnsTrue() {
        AuthorizationServerMetadata metadata = AuthorizationServerMetadata.builder()
                .issuer(EXTERNAL_SERVER_URL)
                .tokenEndpoint(EXTERNAL_SERVER_URL + "/token")
                .grantTypesSupported(Arrays.asList("authorization_code", Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE))
                .build();

        when(vciCacheService.getASMetadata(EXTERNAL_SERVER_URL)).thenReturn(metadata);

        boolean result = authorizationServerService.supportsPreAuthorizedCodeGrant(EXTERNAL_SERVER_URL);

        assertTrue(result);
    }

    @Test
    public void supportsPreAuthorizedCodeGrant_NotSupported_ReturnsFalse() {
        AuthorizationServerMetadata metadata = AuthorizationServerMetadata.builder()
                .issuer(EXTERNAL_SERVER_URL)
                .tokenEndpoint(EXTERNAL_SERVER_URL + "/token")
                .grantTypesSupported(Arrays.asList("authorization_code"))
                .build();

        when(vciCacheService.getASMetadata(EXTERNAL_SERVER_URL)).thenReturn(metadata);

        boolean result = authorizationServerService.supportsPreAuthorizedCodeGrant(EXTERNAL_SERVER_URL);

        assertFalse(result);
    }

    @Test
    public void supportsPreAuthorizedCodeGrant_NullGrantTypes_ReturnsFalse() {
        AuthorizationServerMetadata metadata = AuthorizationServerMetadata.builder()
                .issuer(EXTERNAL_SERVER_URL)
                .tokenEndpoint(EXTERNAL_SERVER_URL + "/token")
                .build();

        when(vciCacheService.getASMetadata(EXTERNAL_SERVER_URL)).thenReturn(metadata);

        boolean result = authorizationServerService.supportsPreAuthorizedCodeGrant(EXTERNAL_SERVER_URL);

        assertFalse(result);
    }

    @Test
    public void supportsPreAuthorizedCodeGrant_DiscoveryFails_ReturnsFalse() {
        when(vciCacheService.getASMetadata(EXTERNAL_SERVER_URL)).thenReturn(null);
        when(restTemplate.getForEntity(any(URI.class), eq(String.class)))
                .thenThrow(new RuntimeException("Connection failed"));

        boolean result = authorizationServerService.supportsPreAuthorizedCodeGrant(EXTERNAL_SERVER_URL);

        assertFalse(result);
    }

    // ========== Tests for getAuthorizationServerForCredentialConfig() ==========

    @Test
    public void getAuthorizationServerForCredentialConfig_MappedAS_ReturnsMapping() throws Exception {
        String configId = "test-config";
        String mappedUrl = "https://mapped-auth.example.com";

        ReflectionTestUtils.setField(authorizationServerService, "authorizationServersConfig", mappedUrl);
        ReflectionTestUtils.setField(authorizationServerService, "credentialConfigMappingJson",
                "{\"" + configId + "\":\"" + mappedUrl + "\"}");

        when(objectMapper.readValue(anyString(), any(TypeReference.class)))
                .thenReturn(Map.of(configId, mappedUrl));

        authorizationServerService.initialize();

        String result = authorizationServerService.getAuthorizationServerForCredentialConfig(configId);

        assertEquals(mappedUrl, result);
    }

    @Test
    public void getAuthorizationServerForCredentialConfig_NoMapping_UsesDefault() throws Exception {
        String configId = "unmapped-config";

        ReflectionTestUtils.setField(authorizationServerService, "defaultAuthServer", DEFAULT_SERVER_URL);
        ReflectionTestUtils.setField(authorizationServerService, "authorizationServersConfig", DEFAULT_SERVER_URL);

        authorizationServerService.initialize();

        String result = authorizationServerService.getAuthorizationServerForCredentialConfig(configId);

        assertEquals(DEFAULT_SERVER_URL, result);
    }

    @Test
    public void getAuthorizationServerForCredentialConfig_NoDefaultOrMapping_UsesInternal() {
        String configId = "some-config";

        ReflectionTestUtils.setField(authorizationServerService, "defaultAuthServer", "");

        authorizationServerService.initialize();

        String result = authorizationServerService.getAuthorizationServerForCredentialConfig(configId);

        assertEquals(INTERNAL_SERVER_URL, result);
    }

    @Test
    public void getAuthorizationServerForCredentialConfig_NoASConfigured_ThrowsCertifyException() {
        String configId = "some-config";

        ReflectionTestUtils.setField(authorizationServerService, "internalAuthServerUrl", "");
        ReflectionTestUtils.setField(authorizationServerService, "defaultAuthServer", "");

        authorizationServerService.initialize();

        CertifyException exception = assertThrows(CertifyException.class,
                () -> authorizationServerService.getAuthorizationServerForCredentialConfig(configId));

        assertEquals(ErrorConstants.AUTHORIZATION_SERVER_NOT_CONFIGURED, exception.getErrorCode());
    }

    @Test
    public void getAuthorizationServerForCredentialConfig_MappedButNotConfigured_ThrowsInvalidRequestException() throws Exception {
        String configId = "test-config";
        String unconfiguredUrl = "https://unconfigured.example.com";

        ReflectionTestUtils.setField(authorizationServerService, "credentialConfigMappingJson",
                "{\"" + configId + "\":\"" + unconfiguredUrl + "\"}");

        when(objectMapper.readValue(anyString(), any(TypeReference.class)))
                .thenReturn(Map.of(configId, unconfiguredUrl));

        authorizationServerService.initialize();

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> authorizationServerService.getAuthorizationServerForCredentialConfig(configId));

        assertEquals(ErrorConstants.INVALID_AUTHORIZATION_SERVER, exception.getErrorCode());
    }

    // ========== Tests for getAllAuthorizationServerUrls() ==========

    @Test
    public void getAllAuthorizationServerUrls_ReturnsAllConfigured() {
        ReflectionTestUtils.setField(authorizationServerService, "authorizationServersConfig",
                "https://ext1.example.com, https://ext2.example.com");

        authorizationServerService.initialize();

        List<String> urls = authorizationServerService.getAllAuthorizationServerUrls();

        assertEquals(3, urls.size());
        assertTrue(urls.contains(INTERNAL_SERVER_URL));
        assertTrue(urls.contains("https://ext1.example.com"));
        assertTrue(urls.contains("https://ext2.example.com"));
    }

    // ========== Tests for isServerConfigured() ==========

    @Test
    public void isServerConfigured_ConfiguredServer_ReturnsTrue() {
        authorizationServerService.initialize();

        boolean result = authorizationServerService.isServerConfigured(INTERNAL_SERVER_URL);

        assertTrue(result);
    }

    @Test
    public void isServerConfigured_ConfiguredServerWithTrailingSlash_ReturnsTrue() {
        authorizationServerService.initialize();

        boolean result = authorizationServerService.isServerConfigured(INTERNAL_SERVER_URL + "/");

        assertTrue(result);
    }

    @Test
    public void isServerConfigured_UnconfiguredServer_ReturnsFalse() {
        authorizationServerService.initialize();

        boolean result = authorizationServerService.isServerConfigured("https://unknown.example.com");

        assertFalse(result);
    }

    // ========== Tests for normalizeUrl() (accessed via reflection) ==========

    @Test
    public void normalizeUrl_RemovesTrailingSlash() {
        authorizationServerService.initialize();

        String result = ReflectionTestUtils.invokeMethod(authorizationServerService, "normalizeUrl",
                "https://example.com/");

        assertEquals("https://example.com", result);
    }

    @Test
    public void normalizeUrl_RemovesMultipleTrailingSlashes() {
        authorizationServerService.initialize();

        String result = ReflectionTestUtils.invokeMethod(authorizationServerService, "normalizeUrl",
                "https://example.com///");

        assertEquals("https://example.com", result);
    }

    @Test
    public void normalizeUrl_NullUrl_ReturnsEmptyString() {
        authorizationServerService.initialize();

        String result = ReflectionTestUtils.invokeMethod(authorizationServerService, "normalizeUrl",
                (String) null);

        assertEquals("", result);
    }

    @Test
    public void normalizeUrl_NoTrailingSlash_ReturnsSame() {
        authorizationServerService.initialize();

        String result = ReflectionTestUtils.invokeMethod(authorizationServerService, "normalizeUrl",
                "https://example.com");

        assertEquals("https://example.com", result);
    }

    // ========== Tests for generateServerId() (accessed via reflection) ==========

    @Test
    public void generateServerId_ValidUrl_GeneratesId() {
        authorizationServerService.initialize();

        String result = ReflectionTestUtils.invokeMethod(authorizationServerService, "generateServerId",
                "https://auth.example.com");

        assertNotNull(result);
        assertTrue(result.startsWith("as-"));
        assertTrue(result.contains("auth-example-com"));
    }

    @Test
    public void generateServerId_UrlWithPort_GeneratesId() {
        authorizationServerService.initialize();

        String result = ReflectionTestUtils.invokeMethod(authorizationServerService, "generateServerId",
                "https://auth.example.com:8080");

        assertNotNull(result);
        assertTrue(result.startsWith("as-"));
    }
}
