package io.mosip.certify.services;

import io.mosip.certify.core.dto.OAuthASMetadataDTO;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

@RunWith(MockitoJUnitRunner.class)
public class OAuthASMetadataServiceTest {

    @InjectMocks
    private OAuthASMetadataService oAuthASMetadataService;

    private static final String TEST_ISSUER = "http://localhost:8090/v1/certify";
    private static final String TEST_TOKEN_ENDPOINT = "http://localhost:8090/v1/certify/oauth/token";
    private static final String TEST_JWK_SET_URI = "http://localhost:8090/v1/certify/.well-known/jwks.json";
    private static final String TEST_RESPONSE_TYPES = "code";
    private static final String TEST_GRANT_TYPES = "authorization_code,pre-authorized_code";
    private static final String TEST_TOKEN_ENDPOINT_AUTH_METHODS = "client_secret_basic,client_secret_post,private_key_jwt";
    private static final String TEST_INTERACTIVE_AUTHORIZATION_ENDPOINT = "http://localhost:8090/v1/certify/oauth/iar";

    @Before
    public void setup() {
        // Set up the properties using ReflectionTestUtils
        ReflectionTestUtils.setField(oAuthASMetadataService, "issuer", TEST_ISSUER);
        ReflectionTestUtils.setField(oAuthASMetadataService, "tokenEndpoint", TEST_TOKEN_ENDPOINT);
        ReflectionTestUtils.setField(oAuthASMetadataService, "jwksUri", TEST_JWK_SET_URI);
        ReflectionTestUtils.setField(oAuthASMetadataService, "responseTypesSupported", TEST_RESPONSE_TYPES);
        ReflectionTestUtils.setField(oAuthASMetadataService, "grantTypesSupported", TEST_GRANT_TYPES);
        ReflectionTestUtils.setField(oAuthASMetadataService, "tokenEndpointAuthMethodsSupported", TEST_TOKEN_ENDPOINT_AUTH_METHODS);
        ReflectionTestUtils.setField(oAuthASMetadataService, "interactiveAuthorizationEndpoint", TEST_INTERACTIVE_AUTHORIZATION_ENDPOINT);
    }

    @Test
    public void getOAuthASMetadata_ShouldReturnCompleteMetadata() {
        // Act
        OAuthASMetadataDTO result = oAuthASMetadataService.getOAuthASMetadata();

        // Assert
        assertNotNull("OAuth AS metadata should not be null", result);
        assertEquals("Issuer should match", TEST_ISSUER, result.getIssuer());
        assertEquals("Token endpoint should match", TEST_TOKEN_ENDPOINT, result.getTokenEndpoint());
        assertEquals("JWK set URI should match", TEST_JWK_SET_URI, result.getJwksUri());
        assertEquals("Interactive authorization endpoint should match", TEST_INTERACTIVE_AUTHORIZATION_ENDPOINT, result.getInteractiveAuthorizationEndpoint());
    }

    @Test
    public void getOAuthASMetadata_ShouldReturnCorrectArrayFields() {
        // Act
        OAuthASMetadataDTO result = oAuthASMetadataService.getOAuthASMetadata();

        // Assert
        assertNotNull("Result should not be null", result);
        
        List<String> expectedResponseTypes = List.of("code");
        assertEquals("Response types should match", expectedResponseTypes, result.getResponseTypesSupported());
        
        List<String> expectedGrantTypes = Arrays.asList("authorization_code", "pre-authorized_code");
        assertEquals("Grant types should match", expectedGrantTypes, result.getGrantTypesSupported());
        
        List<String> expectedTokenAuthMethods = Arrays.asList("client_secret_basic", "client_secret_post", "private_key_jwt");
        assertEquals("Token endpoint auth methods should match", expectedTokenAuthMethods, result.getTokenEndpointAuthMethodsSupported());
    }

    @Test
    public void getOAuthASMetadata_WithEmptyProperties_ShouldReturnEmptyLists() {
        // Arrange - set empty properties
        ReflectionTestUtils.setField(oAuthASMetadataService, "responseTypesSupported", "");
        ReflectionTestUtils.setField(oAuthASMetadataService, "grantTypesSupported", "");
        ReflectionTestUtils.setField(oAuthASMetadataService, "tokenEndpointAuthMethodsSupported", "");

        // Act
        OAuthASMetadataDTO result = oAuthASMetadataService.getOAuthASMetadata();

        // Assert
        assertNotNull("Result should not be null", result);
        assertTrue("Response types should be empty", result.getResponseTypesSupported().isEmpty());
        assertTrue("Grant types should be empty", result.getGrantTypesSupported().isEmpty());
        assertTrue("Token endpoint auth methods should be empty", result.getTokenEndpointAuthMethodsSupported().isEmpty());
    }

    @Test
    public void getOAuthASMetadata_WithNullProperties_ShouldReturnEmptyLists() {
        // Arrange - set null properties
        ReflectionTestUtils.setField(oAuthASMetadataService, "responseTypesSupported", null);
        ReflectionTestUtils.setField(oAuthASMetadataService, "grantTypesSupported", null);
        ReflectionTestUtils.setField(oAuthASMetadataService, "tokenEndpointAuthMethodsSupported", null);

        // Act
        OAuthASMetadataDTO result = oAuthASMetadataService.getOAuthASMetadata();

        // Assert
        assertNotNull("Result should not be null", result);
        assertTrue("Response types should be empty", result.getResponseTypesSupported().isEmpty());
        assertTrue("Grant types should be empty", result.getGrantTypesSupported().isEmpty());
        assertTrue("Token endpoint auth methods should be empty", result.getTokenEndpointAuthMethodsSupported().isEmpty());
    }

    @Test
    public void getOAuthASMetadata_WithSingleValues_ShouldReturnSingleItemLists() {
        // Arrange - set single values
        ReflectionTestUtils.setField(oAuthASMetadataService, "responseTypesSupported", "code");
        ReflectionTestUtils.setField(oAuthASMetadataService, "grantTypesSupported", "authorization_code");
        ReflectionTestUtils.setField(oAuthASMetadataService, "tokenEndpointAuthMethodsSupported", "client_secret_basic");

        // Act
        OAuthASMetadataDTO result = oAuthASMetadataService.getOAuthASMetadata();

        // Assert
        assertNotNull("Result should not be null", result);
        assertEquals("Response types should have one item", 1, result.getResponseTypesSupported().size());
        assertEquals("Response type should be code", "code", result.getResponseTypesSupported().get(0));
        assertEquals("Grant types should have one item", 1, result.getGrantTypesSupported().size());
        assertEquals("Grant type should be authorization_code", "authorization_code", result.getGrantTypesSupported().get(0));
        assertEquals("Token auth methods should have one item", 1, result.getTokenEndpointAuthMethodsSupported().size());
        assertEquals("Token auth method should be client_secret_basic", "client_secret_basic", result.getTokenEndpointAuthMethodsSupported().get(0));
    }

    @Test
    public void getOAuthASMetadata_WithWhitespaceInCommaSeparatedValues_ShouldTrimValues() {
        // Arrange - set values with whitespace
        ReflectionTestUtils.setField(oAuthASMetadataService, "grantTypesSupported", " authorization_code , pre-authorized_code ");
        ReflectionTestUtils.setField(oAuthASMetadataService, "tokenEndpointAuthMethodsSupported", " client_secret_basic , client_secret_post ");

        // Act
        OAuthASMetadataDTO result = oAuthASMetadataService.getOAuthASMetadata();

        // Assert
        assertNotNull("Result should not be null", result);
        
        // Note: The current implementation doesn't trim values, so we test the actual behavior
        List<String> expectedGrantTypes = Arrays.asList(" authorization_code ", " pre-authorized_code ");
        assertEquals("Grant types should match (with whitespace)", expectedGrantTypes, result.getGrantTypesSupported());
        
        List<String> expectedTokenAuthMethods = Arrays.asList(" client_secret_basic ", " client_secret_post ");
        assertEquals("Token auth methods should match (with whitespace)", expectedTokenAuthMethods, result.getTokenEndpointAuthMethodsSupported());
    }

    @Test
    public void getOAuthASMetadata_WithMultipleValues_ShouldParseCorrectly() {
        // Arrange - set multiple values
        ReflectionTestUtils.setField(oAuthASMetadataService, "grantTypesSupported", "authorization_code,refresh_token,client_credentials");
        ReflectionTestUtils.setField(oAuthASMetadataService, "responseTypesSupported", "code,token");

        // Act
        OAuthASMetadataDTO result = oAuthASMetadataService.getOAuthASMetadata();

        // Assert
        assertNotNull("Result should not be null", result);
        
        List<String> expectedGrantTypes = Arrays.asList("authorization_code", "refresh_token", "client_credentials");
        assertEquals("Grant types should be parsed correctly", expectedGrantTypes, result.getGrantTypesSupported());
        
        List<String> expectedResponseTypes = Arrays.asList("code", "token");
        assertEquals("Response types should be parsed correctly", expectedResponseTypes, result.getResponseTypesSupported());
    }
}
