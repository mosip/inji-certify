package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;

import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.api.util.Action;
import io.mosip.certify.api.util.ActionStatus;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.SignatureAlg;

import io.mosip.certify.core.dto.*;


import io.mosip.certify.core.exception.CertifyException;

import io.mosip.certify.credential.CredentialFactory;
import io.mosip.certify.credential.SDJWT; // Implementation
import io.mosip.certify.credential.W3cJsonLd; // Implementation
import io.mosip.certify.exception.InvalidNonceException;
import io.mosip.certify.proof.ProofValidator;

import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.exception.NotAuthenticatedException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.util.SecurityHelperService;
import io.mosip.certify.proof.ProofValidatorFactory;

import io.mosip.kernel.keymanagerservice.service.KeymanagerService;

import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class CertifyIssuanceServiceImplTest {

    private LinkedHashMap<String, LinkedHashMap<String, Object>> testIssuerMetadataMap;

    @Mock
    private ParsedAccessToken parsedAccessToken;
    @Mock
    private VCFormatter vcFormatter;
    @Mock
    private DataProviderPlugin dataProviderPlugin;
    @Mock
    private ProofValidatorFactory proofValidatorFactory;
    @Mock
    private VCICacheService vciCacheService;
    @Mock
    private SecurityHelperService securityHelperService;
    @Mock
    private AuditPlugin auditWrapper;
    @Mock
    private ProofValidator proofValidator;

    @Mock
    private CredentialFactory credentialFactory;
    @Mock
    private KeymanagerService keymanagerService;
    @Mock
    private CredentialConfigurationService credentialConfigurationService;

    @InjectMocks
    private CertifyIssuanceServiceImpl issuanceService;

    private static final String TEST_ACCESS_TOKEN_HASH = "test-token-hash";
    private static final String TEST_CNONCE = "test-cnonce";
    private static final String DEFAULT_SCOPE = "test-scope";
    private static final String DEFAULT_FORMAT_LDP = VCFormats.LDP_VC;
    private static final String DEFAULT_FORMAT_SDJWT = VCFormats.LDP_SD_JWT; // vc+sd-jwt

    CredentialRequest request;
    Map<String, Object> claimsFromAccessToken; // Renamed for clarity
    VCIssuanceTransaction transaction;
    CredentialIssuerMetadataVD13DTO mockGlobalCredentialIssuerMetadataDTO;


    @Before
    public void setUp() {
        testIssuerMetadataMap = new LinkedHashMap<>();
        LinkedHashMap<String, Object> latestMetadataConfig = new LinkedHashMap<>();
        LinkedHashMap<String, Object> credentialConfigurationsSupportedMapForTestMeta = new LinkedHashMap<>();
        LinkedHashMap<String, Object> vcConfigForTestMeta = new LinkedHashMap<>();
        vcConfigForTestMeta.put("format", DEFAULT_FORMAT_LDP);
        vcConfigForTestMeta.put("scope", DEFAULT_SCOPE);
        // ... (rest of the population for testIssuerMetadataMap as before)
        LinkedHashMap<String, Object> credDefMapForTestMeta = new LinkedHashMap<>();
        credDefMapForTestMeta.put("type", Arrays.asList("VerifiableCredential", "TestCredential"));
        vcConfigForTestMeta.put("credential_definition", credDefMapForTestMeta);
        credentialConfigurationsSupportedMapForTestMeta.put("test-credential-id", vcConfigForTestMeta);
        latestMetadataConfig.put("credential_configurations_supported", credentialConfigurationsSupportedMapForTestMeta);
        latestMetadataConfig.put("credential_issuer", "https://localhost:9090");
        latestMetadataConfig.put("credential_endpoint", "https://localhost:9090/v1/certify/issuance/credential");
        testIssuerMetadataMap.put("latest", latestMetadataConfig);


        ReflectionTestUtils.setField(issuanceService, "issuerMetadata", testIssuerMetadataMap);
        ReflectionTestUtils.setField(issuanceService, "vcSignAlgorithm", SignatureAlg.ED25519_SIGNATURE_SUITE_2020);
        ReflectionTestUtils.setField(issuanceService, "cNonceExpireSeconds", 300);
        ReflectionTestUtils.setField(issuanceService, "issuerURI", "https://test.issuer.com");
        ReflectionTestUtils.setField(issuanceService, "issuerPublicKeyURI", "http://example.com/issuer#key-1");

        when(parsedAccessToken.getAccessTokenHash()).thenReturn(TEST_ACCESS_TOKEN_HASH);

        claimsFromAccessToken = new HashMap<>();
        claimsFromAccessToken.put("scope", DEFAULT_SCOPE);
        claimsFromAccessToken.put("client_id", "test-client");

        transaction = new VCIssuanceTransaction();
        transaction.setCNonce(TEST_CNONCE);
        transaction.setCNonceExpireSeconds(300);
        transaction.setCNonceIssuedEpoch(LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC));


        mockGlobalCredentialIssuerMetadataDTO = new CredentialIssuerMetadataVD13DTO();
        mockGlobalCredentialIssuerMetadataDTO.setCredentialIssuer("https://test.issuer.com");
        mockGlobalCredentialIssuerMetadataDTO.setAuthorizationServers(List.of("https://auth.server.com"));
        mockGlobalCredentialIssuerMetadataDTO.setCredentialEndpoint("https://test.issuer.com/credentials");

        Map<String, CredentialConfigurationSupportedDTO> supportedCredsMap = new HashMap<>();

        // LDP Config DTO
        CredentialConfigurationSupportedDTO supportedDTO_LDP = new CredentialConfigurationSupportedDTO();
        supportedDTO_LDP.setScope(DEFAULT_SCOPE);
        supportedDTO_LDP.setFormat(DEFAULT_FORMAT_LDP);
        CredentialDefinition credDefDtoForLDP = new CredentialDefinition(); // Using your DTO structure
        credDefDtoForLDP.setContext(List.of("https://www.w3.org/2018/credentials/v1"));
        credDefDtoForLDP.setType(List.of("VerifiableCredential", "TestCredential"));
        supportedDTO_LDP.setCredentialDefinition(credDefDtoForLDP);
        supportedCredsMap.put("test-credential-id-ldp", supportedDTO_LDP);

        // SD-JWT Config DTO
        CredentialConfigurationSupportedDTO supportedDTO_SDJWT = new CredentialConfigurationSupportedDTO();
        supportedDTO_SDJWT.setScope(DEFAULT_SCOPE);
        supportedDTO_SDJWT.setFormat(DEFAULT_FORMAT_SDJWT);
        CredentialDefinition credDefDtoForSDJWT = new CredentialDefinition(); // Using your DTO structure
        credDefDtoForSDJWT.setContext(List.of("https://www.w3.org/2018/credentials/v1", "https://example.org/sd-jwt/v1"));
        credDefDtoForSDJWT.setType(List.of("VerifiableCredential", "TestCredential", "SDJWTCredential"));
        supportedDTO_SDJWT.setCredentialDefinition(credDefDtoForSDJWT);
        supportedCredsMap.put("test-credential-id-sdjwt", supportedDTO_SDJWT);

        mockGlobalCredentialIssuerMetadataDTO.setCredentialConfigurationSupportedDTO(supportedCredsMap);

        when(credentialConfigurationService.fetchCredentialIssuerMetadata("latest"))
                .thenReturn(mockGlobalCredentialIssuerMetadataDTO); // Default mock
    }

    private CredentialRequest createValidCredentialRequest(String format) {
        CredentialRequest req = new CredentialRequest();
        req.setFormat(format);
        req.setVct("test_vct");

        // This is io.mosip.certify.core.dto.CredentialDefinition for the request object
        io.mosip.certify.core.dto.CredentialDefinition requestCredDef = new io.mosip.certify.core.dto.CredentialDefinition();
        if (DEFAULT_FORMAT_SDJWT.equals(format)) {
            requestCredDef.setContext(List.of("https://www.w3.org/2018/credentials/v1", "https://example.org/sd-jwt/v1"));
            requestCredDef.setType(List.of("VerifiableCredential", "TestCredential", "SDJWTCredential"));
        } else { // LDP
            requestCredDef.setContext(List.of("https://www.w3.org/2018/credentials/v1"));
            requestCredDef.setType(List.of("VerifiableCredential", "TestCredential"));
        }
        requestCredDef.setCredentialSubject(new HashMap<>());
        req.setCredential_definition(requestCredDef);

        CredentialProof proof = new CredentialProof();
        proof.setProof_type("jwt");
        proof.setJwt("dummy.jwt.token");
        req.setProof(proof);
        return req;
    }

    @Test
    public void getCredential_LDP_WithValidTransaction_Success() throws DataProviderExchangeException, JsonLDException, GeneralSecurityException, IOException {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);

        // Stub getKeyMaterial, its result is used in templateParams for createCredential
        when(proofValidator.getKeyMaterial(any(CredentialProof.class))).thenReturn("");

        when(proofValidator.validateV2(eq("test-client"), eq(TEST_CNONCE), any(CredentialProof.class), any())).thenReturn(true);
        when(dataProviderPlugin.fetchData(claimsFromAccessToken)).thenReturn(new JSONObject().put("subjectKey", "subjectValue"));

        W3cJsonLd mockW3cJsonLd = mock(W3cJsonLd.class);
        when(credentialFactory.getCredential(DEFAULT_FORMAT_LDP)).thenReturn(Optional.of(mockW3cJsonLd));
        when(mockW3cJsonLd.createCredential(anyMap(), anyString())).thenReturn("{\"unsigned\":\"credential\"}");

        // Stub vcFormatter methods called by service's getVerifiableCredential method for addProof
        when(vcFormatter.getProofAlgorithm(anyString())).thenReturn("EdDSA"); // Example value
        when(vcFormatter.getAppID(anyString())).thenReturn("testAppIdLdp");   // Example value
        when(vcFormatter.getRefID(anyString())).thenReturn("testRefIdLdp");   // Example value
        when(vcFormatter.getDidUrl(anyString())).thenReturn("did:example:ldp"); // Example value

        // Corrected declaration of mockVcResultLdp
        VCResult mockVcResultLdp = new VCResult<JsonLDObject>();
        JsonLDObject signedCredObj = JsonLDObject.fromJson("{\"signed\":\"credential\", \"proof\":{}}");
        mockVcResultLdp.setCredential(signedCredObj);

        // The holderId argument to addProof in the service is "" for LDP
        when(mockW3cJsonLd.addProof(
                eq("{\"unsigned\":\"credential\"}"),
                eq(""),  // Service code passes "" for LDP's addProof holderId
                anyString(),
                anyString(),
                anyString(),
                anyString()
        )).thenReturn(mockVcResultLdp);

        CredentialResponse<?> response = issuanceService.getCredential(request);

        assertNotNull("CredentialResponse should not be null", response);
        assertNotNull("Response credential should not be null", response.getCredential());
        assertTrue("Response credential should be JsonLDObject", response.getCredential() instanceof JsonLDObject);
        // Refined audit log matcher
        verify(auditWrapper).logAudit(eq(Action.VC_ISSUANCE), eq(ActionStatus.SUCCESS), any(), isNull());
    }

    @Test
    public void getCredential_UnsupportedFormatHandledByFactory_Fail() throws DataProviderExchangeException {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.validateV2(anyString(), anyString(), any(CredentialProof.class),any())).thenReturn(true);
        when(dataProviderPlugin.fetchData(anyMap())).thenReturn(new JSONObject());
        when(credentialFactory.getCredential(DEFAULT_FORMAT_LDP)).thenReturn(Optional.empty());

        CertifyException ex = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals(ErrorConstants.UNSUPPORTED_VC_FORMAT, ex.getErrorCode());
    }

    @Test
    public void getCredential_ValidRequest_DataProviderException_Fail() throws DataProviderExchangeException {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.validateV2(anyString(), anyString(), any(CredentialProof.class),any())).thenReturn(true);
        DataProviderExchangeException e = new DataProviderExchangeException("DP_FETCH_FAILED", "Failed to fetch data");
        when(dataProviderPlugin.fetchData(claimsFromAccessToken)).thenThrow(e);

        CertifyException ex = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals("DP_FETCH_FAILED", ex.getErrorCode());
    }

    @Test
    public void getCredential_ExpiredNonce_ThrowsInvalidNonceException() {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);
        VCIssuanceTransaction expiredTransaction = new VCIssuanceTransaction();
        expiredTransaction.setCNonce("expired-cnonce");
        expiredTransaction.setCNonceExpireSeconds(10);
        expiredTransaction.setCNonceIssuedEpoch(LocalDateTime.now(ZoneOffset.UTC).minusSeconds(20).toEpochSecond(ZoneOffset.UTC));

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(expiredTransaction);
        when(securityHelperService.generateSecureRandomString(anyInt())).thenReturn("new-generated-cnonce");
        when(vciCacheService.setVCITransaction(eq(TEST_ACCESS_TOKEN_HASH), any(VCIssuanceTransaction.class)))
                .thenAnswer(invocation -> invocation.getArgument(1));

        assertThrows(InvalidNonceException.class, () -> issuanceService.getCredential(request));
    }

    @Test
    public void getCredential_NullTransactionForCNonceAndNoCNonceInToken_ThrowsInvalidNonceException() {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);
        Map<String, Object> claimsWithoutCNonce = new HashMap<>(claimsFromAccessToken);
        claimsWithoutCNonce.remove(Constants.C_NONCE); // Ensure c_nonce isn't in access token claims
        claimsWithoutCNonce.remove(Constants.C_NONCE_EXPIRES_IN);


        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsWithoutCNonce);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(null);
        when(securityHelperService.generateSecureRandomString(anyInt())).thenReturn("new-generated-cnonce");
        when(vciCacheService.setVCITransaction(eq(TEST_ACCESS_TOKEN_HASH), any(VCIssuanceTransaction.class)))
                .thenAnswer(invocation -> invocation.getArgument(1));

        assertThrows(InvalidNonceException.class, () -> issuanceService.getCredential(request));
    }

    @Test
    public void getCredential_RequestValidatorFails_ThrowsInvalidRequestException() {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);
        request.setFormat("invalid format with spaces");
        InvalidRequestException ex = assertThrows(InvalidRequestException.class, () -> issuanceService.getCredential(request));
        assertEquals(ErrorConstants.UNSUPPORTED_VC_FORMAT, ex.getErrorCode());
    }

    @Test
    public void getCredential_InvalidScope_Fail() {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);
        Map<String, Object> claimsWithInvalidScope = new HashMap<>(claimsFromAccessToken);
        claimsWithInvalidScope.put("scope", "unknown-scope");

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsWithInvalidScope);
        // mockGlobalCredentialIssuerMetadataDTO (from setUp) is configured for DEFAULT_SCOPE.
        // So, "unknown-scope" will not be found by VCIssuanceUtil.getScopeCredentialMapping.

        CertifyException ex = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals(ErrorConstants.INVALID_SCOPE, ex.getErrorCode());
    }

    @Test
    public void getCredential_InvalidProof_Fail() {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.validateV2(anyString(), anyString(), any(CredentialProof.class),any())).thenReturn(false);

        CertifyException ex = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals(ErrorConstants.INVALID_PROOF, ex.getErrorCode());
    }

    @Test
    public void getCredentialIssuerMetadata_validLatest() {
        Map<String, Object> actual = issuanceService.getCredentialIssuerMetadata("latest");
        assertNotNull(actual);
        assertSame(testIssuerMetadataMap.get("latest"), actual);
    }

    @Test
    public void getCredentialIssuerMetadata_validVD11() {
        Map<String, Object> actual = issuanceService.getCredentialIssuerMetadata("vd11");
        assertNotNull(actual);
        assertTrue(actual.containsKey("credentials_supported"));
        assertEquals("https://localhost:9090/v1/certify/issuance/vd11/credential", actual.get("credential_endpoint"));
    }

    @Test
    public void getCredentialIssuerMetadata_validVD12() {
        Map<String, Object> actual = issuanceService.getCredentialIssuerMetadata("vd12");
        assertNotNull(actual);
        assertTrue(actual.containsKey("credentials_supported"));
        assertEquals("https://localhost:9090/v1/certify/issuance/vd12/credential", actual.get("credential_endpoint"));
    }

    @Test
    public void getCredentialIssuerMetadata_UnsupportedVersion_ThrowsInvalidRequestException() {
        InvalidRequestException ex = assertThrows(InvalidRequestException.class, () -> issuanceService.getCredentialIssuerMetadata("unsupportedVersion"));
        assertEquals(ErrorConstants.UNSUPPORTED_OPENID_VERSION, ex.getErrorCode());
    }

    @Test
    public void getCredentialIssuerMetadata_NullVersion_ThrowsInvalidRequestException() {
        InvalidRequestException ex = assertThrows(InvalidRequestException.class, () -> issuanceService.getCredentialIssuerMetadata(null));
        assertEquals(ErrorConstants.UNSUPPORTED_OPENID_VERSION, ex.getErrorCode());
    }

    @Test
    public void getVerifiableCredential_NotAuthenticated_ThrowsNotAuthenticatedException() {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);
        when(parsedAccessToken.isActive()).thenReturn(false);
        assertThrows(NotAuthenticatedException.class, () -> issuanceService.getCredential(request));
    }

    @Test
    public void getCredential_SDJWT_Success() throws Exception {
        request = createValidCredentialRequest(DEFAULT_FORMAT_SDJWT);

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);

        // Crucial: Stub getKeyMaterial to return "" to match the addProof mock
        when(proofValidator.getKeyMaterial(any(CredentialProof.class))).thenReturn("");

        when(proofValidator.validateV2(anyString(), eq(TEST_CNONCE), any(CredentialProof.class), any())).thenReturn(true);
        when(dataProviderPlugin.fetchData(claimsFromAccessToken)).thenReturn(new JSONObject().put("key", "value"));

        SDJWT mockSdJwt = mock(SDJWT.class);
        when(credentialFactory.getCredential(DEFAULT_FORMAT_SDJWT)).thenReturn(Optional.of(mockSdJwt));
        when(mockSdJwt.createCredential(anyMap(), anyString())).thenReturn("{\"unsigned\":\"sdjwt_payload\"}");

        // Corrected declaration of mockVcResultSdJwt
        VCResult mockVcResultSdJwt = new VCResult<String>();
        mockVcResultSdJwt.setCredential("signed.sdjwt.string~disclosure1~disclosure2");

        // Ensure vcFormatter methods are mocked if they are called and their results are important
        // For anyString() matchers in addProof, nulls are fine, but it's good practice if specific values are expected elsewhere
        when(vcFormatter.getProofAlgorithm(anyString())).thenReturn("EdDSA"); // Example value
        when(vcFormatter.getAppID(anyString())).thenReturn("testAppId");       // Example value
        when(vcFormatter.getRefID(anyString())).thenReturn("testRefId");       // Example value
        when(vcFormatter.getDidUrl(anyString())).thenReturn("did:example:123"); // Example value


        when(mockSdJwt.addProof(
                eq("{\"unsigned\":\"sdjwt_payload\"}"), // unsignedCredential
                eq(""),                                 // holderId (now matches due to getKeyMaterial stub)
                anyString(),                            // proofAlgorithm
                anyString(),                            // keyManagerAppId
                anyString(),                            // keyManagerRefId
                anyString()                             // didUrl
        )).thenReturn(mockVcResultSdJwt);           // Use thenReturn for now

        CredentialResponse<?> response = issuanceService.getCredential(request);

        assertNotNull("CredentialResponse should not be null", response);
        assertNotNull("Response credential should not be null", response.getCredential());
        assertTrue("Response credential should be a String", response.getCredential() instanceof String);
        String credential = (String) response.getCredential();
        assertTrue("Credential string should contain SD-JWT disclosure separator '~'", credential.contains("~"));
        verify(auditWrapper).logAudit(any(), any(), any(), isNull());
    }

    @Test
    public void testGetDIDDocument_whenDidDocumentAlreadySet() {
        // Arrange
        Map<String, Object> expectedDocument = new HashMap<>();
        expectedDocument.put("key", "value");  // Sample data
        ReflectionTestUtils.setField(issuanceService, "didDocument", expectedDocument); // assuming a setter or constructor to set it

        // Act
        Map<String, Object> result = issuanceService.getDIDDocument();

        // Assert
        assertEquals(expectedDocument, result);
        verify(keymanagerService, times(0)).getCertificate(any(), any());  // Verifying that no call was made to keymanagerService
    }
}