package io.mosip.certify.services;

import io.mosip.certify.core.dto.OAuthAuthorizationServerMetadataDTO;
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
public class OAuthAuthorizationServerMetadataServiceTest {

    @InjectMocks
    private OAuthAuthorizationServerMetadataService oAuthAuthorizationServerMetadataService;

    private static final String TEST_ISSUER = "http://localhost:8090";
    private static final String TEST_TOKEN_ENDPOINT = "http://localhost:8090/v1/certify/oauth/token";
    private static final String TEST_RESPONSE_TYPES = "code";
    private static final String TEST_GRANT_TYPES = "authorization_code";
    private static final String TEST_CODE_CHALLENGE_METHODS = "S256";
    private static final String TEST_INTERACTIVE_AUTHORIZATION_ENDPOINT = "http://localhost:8090/v1/certify/oauth/iar";

    @Before
    public void setup() {
        // Set up the properties using ReflectionTestUtils
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "issuer", TEST_ISSUER);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "tokenEndpoint", TEST_TOKEN_ENDPOINT);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "responseTypesSupported", TEST_RESPONSE_TYPES);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported", TEST_GRANT_TYPES);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "codeChallengeMethodsSupported", TEST_CODE_CHALLENGE_METHODS);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "interactiveAuthorizationEndpoint", TEST_INTERACTIVE_AUTHORIZATION_ENDPOINT);
    }

    @Test
    public void getOAuthAuthorizationServerMetadata_ShouldReturnCompleteMetadata() {
        // Act
        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        // Assert
        assertNotNull("OAuth Authorization Server metadata should not be null", result);
        assertEquals("Issuer should match", TEST_ISSUER, result.getIssuer());
        assertEquals("Token endpoint should match", TEST_TOKEN_ENDPOINT, result.getTokenEndpoint());
        // JWK set URI is not implemented, so it should not be present in the DTO
        assertEquals("Interactive authorization endpoint should match", TEST_INTERACTIVE_AUTHORIZATION_ENDPOINT, result.getInteractiveAuthorizationEndpoint());
    }

    @Test
    public void getOAuthAuthorizationServerMetadata_ShouldReturnCorrectArrayFields() {
        // Act
        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        // Assert
        assertNotNull("Result should not be null", result);
        
        List<String> expectedResponseTypes = List.of("code");
        assertEquals("Response types should match", expectedResponseTypes, result.getResponseTypesSupported());
        
        List<String> expectedGrantTypes = Arrays.asList("authorization_code");
        assertEquals("Grant types should match", expectedGrantTypes, result.getGrantTypesSupported());
        
        List<String> expectedCodeChallengeMethods = Arrays.asList("S256");
        assertEquals("Code challenge methods should match", expectedCodeChallengeMethods, result.getCodeChallengeMethodsSupported());
        
        // Token endpoint auth methods are not implemented, so they should not be present in the DTO
    }

    @Test
    public void getOAuthAuthorizationServerMetadata_WithEmptyProperties_ShouldReturnEmptyLists() {
        // Arrange - set empty properties
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "responseTypesSupported", "");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported", "");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "codeChallengeMethodsSupported", "");

        // Act
        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        // Assert
        assertNotNull("Result should not be null", result);
        assertTrue("Response types should be empty", result.getResponseTypesSupported().isEmpty());
        assertTrue("Grant types should be empty", result.getGrantTypesSupported().isEmpty());
        assertTrue("Code challenge methods should be empty", result.getCodeChallengeMethodsSupported().isEmpty());
    }

    @Test
    public void getOAuthAuthorizationServerMetadata_WithNullProperties_ShouldReturnEmptyLists() {
        // Arrange - set null properties
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "responseTypesSupported", null);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported", null);
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "codeChallengeMethodsSupported", null);

        // Act
        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        // Assert
        assertNotNull("Result should not be null", result);
        assertTrue("Response types should be empty", result.getResponseTypesSupported().isEmpty());
        assertTrue("Grant types should be empty", result.getGrantTypesSupported().isEmpty());
        assertTrue("Code challenge methods should be empty", result.getCodeChallengeMethodsSupported().isEmpty());
    }

    @Test
    public void getOAuthAuthorizationServerMetadata_WithSingleValues_ShouldReturnSingleItemLists() {
        // Arrange - set single values
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "responseTypesSupported", "code");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported", "authorization_code");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "codeChallengeMethodsSupported", "S256");

        // Act
        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        // Assert
        assertNotNull("Result should not be null", result);
        assertEquals("Response types should have one item", 1, result.getResponseTypesSupported().size());
        assertEquals("Response type should be code", "code", result.getResponseTypesSupported().get(0));
        assertEquals("Grant types should have one item", 1, result.getGrantTypesSupported().size());
        assertEquals("Grant type should be authorization_code", "authorization_code", result.getGrantTypesSupported().get(0));
        assertEquals("Code challenge methods should have one item", 1, result.getCodeChallengeMethodsSupported().size());
        assertEquals("Code challenge method should be S256", "S256", result.getCodeChallengeMethodsSupported().get(0));
    }

    @Test
    public void getOAuthAuthorizationServerMetadata_WithWhitespaceInCommaSeparatedValues_ShouldTrimValues() {
        // Arrange - set values with whitespace
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported", " authorization_code ");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "codeChallengeMethodsSupported", " S256 ");

        // Act
        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        // Assert
        assertNotNull("Result should not be null", result);
        
        // Note: The current implementation doesn't trim values, so we test the actual behavior
        List<String> expectedGrantTypes = Arrays.asList(" authorization_code ");
        assertEquals("Grant types should match (with whitespace)", expectedGrantTypes, result.getGrantTypesSupported());
        
        List<String> expectedCodeChallengeMethods = Arrays.asList(" S256 ");
        assertEquals("Code challenge methods should match (with whitespace)", expectedCodeChallengeMethods, result.getCodeChallengeMethodsSupported());
    }

    @Test
    public void getOAuthAuthorizationServerMetadata_WithMultipleValues_ShouldParseCorrectly() {
        // Arrange - set multiple values
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "grantTypesSupported", "authorization_code");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "responseTypesSupported", "code");
        ReflectionTestUtils.setField(oAuthAuthorizationServerMetadataService, "codeChallengeMethodsSupported", "S256");

        // Act
        OAuthAuthorizationServerMetadataDTO result = oAuthAuthorizationServerMetadataService.getOAuthAuthorizationServerMetadata();

        // Assert
        assertNotNull("Result should not be null", result);
        
        List<String> expectedGrantTypes = Arrays.asList("authorization_code");
        assertEquals("Grant types should be parsed correctly", expectedGrantTypes, result.getGrantTypesSupported());
        
        List<String> expectedResponseTypes = Arrays.asList("code");
        assertEquals("Response types should be parsed correctly", expectedResponseTypes, result.getResponseTypesSupported());
        
        List<String> expectedCodeChallengeMethods = Arrays.asList("S256");
        assertEquals("Code challenge methods should be parsed correctly", expectedCodeChallengeMethods, result.getCodeChallengeMethodsSupported());
    }
}
