package io.mosip.certify.services;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.api.util.Action;
import io.mosip.certify.api.util.ActionStatus;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.exception.NotAuthenticatedException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.util.SecurityHelperService;
import io.mosip.certify.credential.CredentialFactory;
import io.mosip.certify.credential.SDJWT;
import io.mosip.certify.credential.W3CJsonLD;
import io.mosip.certify.exception.InvalidNonceException;
import io.mosip.certify.proof.ProofValidator;
import io.mosip.certify.proof.ProofValidatorFactory;
import io.mosip.certify.utils.LedgerUtils;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.text.ParseException;
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
    @Mock
    private LedgerUtils ledgerUtils;
    @Mock
    private StatusListCredentialService statusListCredentialService;

    @InjectMocks
    private CertifyIssuanceServiceImpl issuanceService;

    private static final String TEST_ACCESS_TOKEN_HASH = "test-token-hash";
    private static final String TEST_CNONCE = "test-cnonce";
    private static final String DEFAULT_SCOPE = "test-scope";
    private static final String DEFAULT_FORMAT_LDP = VCFormats.LDP_VC;
    private static final String DEFAULT_FORMAT_SDJWT = VCFormats.VC_SD_JWT; // vc+sd-jwt

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


        ReflectionTestUtils.setField(issuanceService, "cNonceExpireSeconds", 300);
        ReflectionTestUtils.setField(issuanceService, "didUrl", "https://test.issuer.com");
        ReflectionTestUtils.setField(issuanceService, "ledgerUtils", ledgerUtils);
        ReflectionTestUtils.setField(issuanceService, "statusListCredentialService", statusListCredentialService);

        when(parsedAccessToken.getAccessTokenHash()).thenReturn(TEST_ACCESS_TOKEN_HASH);

        claimsFromAccessToken = new HashMap<>();
        claimsFromAccessToken.put("scope", DEFAULT_SCOPE);
        claimsFromAccessToken.put("client_id", "test-client");
        claimsFromAccessToken.put(Constants.C_NONCE, TEST_CNONCE);

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

        CredentialConfigurationSupportedDTO supportedDTO_LDP_DM2_0 = new CredentialConfigurationSupportedDTO();
        supportedDTO_LDP_DM2_0.setScope(DEFAULT_SCOPE);
        supportedDTO_LDP_DM2_0.setFormat(DEFAULT_FORMAT_LDP);
        CredentialDefinition credDefDtoForLDP_DM2_0 = new CredentialDefinition(); // Using your DTO structure
        credDefDtoForLDP_DM2_0.setContext(List.of("https://www.w3.org/ns/credentials/v2"));
        credDefDtoForLDP_DM2_0.setType(List.of("VerifiableCredential", "TestCredential"));
        supportedDTO_LDP_DM2_0.setCredentialDefinition(credDefDtoForLDP_DM2_0);
        supportedCredsMap.put("test-credential-id-ldp-dm-2.0", supportedDTO_LDP_DM2_0);

        // SD-JWT Config DTO
        CredentialConfigurationSupportedDTO supportedDTO_SDJWT = new CredentialConfigurationSupportedDTO();
        supportedDTO_SDJWT.setScope(DEFAULT_SCOPE);
        supportedDTO_SDJWT.setFormat(DEFAULT_FORMAT_SDJWT);
        supportedDTO_SDJWT.setVct("test_vct");
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
        proof.setProof_type("openid4vci-proof+jwt");

        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey r;
        try {
            r = rsaKeyGenerator.generate();
        } catch (JOSEException e) {
            fail("failed to generate an RSA Keypair");
            throw new RuntimeException(e);
        }
        JWSHeader proofJwtHeader = new JWSHeader(JWSAlgorithm.RS256, new JOSEObjectType("openid4vci-proof+jwt"), null, null, null,
                r.toPublicJWK(), null, null, null, null, null, null, null);
        JWTClaimsSet proofJwtBody;
        try {
            Map<String, Object> pj = Map.of("aud", "fake-aud", "nonce", TEST_CNONCE, "iss", "test-client");
            proofJwtBody = JWTClaimsSet.parse(pj);
        } catch (ParseException e) {
            fail("failed to create a JWTClaimsSet");
            throw new RuntimeException(e);
        }
        SignedJWT requestProofJWT = new SignedJWT(proofJwtHeader, proofJwtBody);
        try {
            JWSSigner rsaSigner = new RSASSASigner(r);
            requestProofJWT.sign(rsaSigner);
        } catch (JOSEException e) {
            fail("failed to create a signer");
        }
        proof.setJwt(requestProofJWT.serialize());
        req.setProof(proof);
        return req;
    }

    @Test
    public void getCredential_LDP_WithValidTransaction_Success() throws DataProviderExchangeException {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);

        // Stub getKeyMaterial, its result is used in templateParams for createCredential
        when(proofValidator.getKeyMaterial(any(CredentialProof.class))).thenReturn("");

        when(proofValidator.validate(eq("test-client"), eq(TEST_CNONCE), any(CredentialProof.class), any())).thenReturn(true);
        when(dataProviderPlugin.fetchData(claimsFromAccessToken)).thenReturn(new JSONObject().put("subjectKey", "subjectValue"));

        W3CJsonLD mockW3CJsonLD = mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(DEFAULT_FORMAT_LDP)).thenReturn(Optional.of(mockW3CJsonLD));
        when(mockW3CJsonLD.createCredential(anyMap(), anyString())).thenReturn("{\"unsigned\":\"credential\"}");

        // Stub vcFormatter methods called by service's getVerifiableCredential method for addProof
        when(vcFormatter.getProofAlgorithm(anyString())).thenReturn("EdDSA"); // Example value
        when(vcFormatter.getAppID(anyString())).thenReturn("testAppIdLdp");   // Example value
        when(vcFormatter.getRefID(anyString())).thenReturn("testRefIdLdp");   // Example value
        when(vcFormatter.getDidUrl(anyString())).thenReturn("did:example:ldp"); // Example value
        when(vcFormatter.getSignatureCryptoSuite(anyString())).thenReturn("testSignatureCryptoSuite"); // Example Value

        // Corrected declaration of mockVcResultLdp
        VCResult mockVcResultLdp = new VCResult<JsonLDObject>();
        JsonLDObject signedCredObj = JsonLDObject.fromJson("{\"signed\":\"credential\", \"proof\":{}}");
        mockVcResultLdp.setCredential(signedCredObj);

        // The holderId argument to addProof in the service is "" for LDP
        when(mockW3CJsonLD.addProof(
                eq("{\"unsigned\":\"credential\"}"),
                eq(""),  // Service code passes "" for LDP's addProof holderId
                anyString(),
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
        when(proofValidator.validate(anyString(), anyString(), any(CredentialProof.class),any())).thenReturn(true);
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
        when(proofValidator.validate(anyString(), anyString(), any(CredentialProof.class),any())).thenReturn(true);
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
        when(proofValidator.validate(anyString(), anyString(), any(CredentialProof.class),any())).thenReturn(false);

        CertifyException ex = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals(ErrorConstants.INVALID_PROOF, ex.getErrorCode());
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

        when(proofValidator.validate(anyString(), eq(TEST_CNONCE), any(CredentialProof.class), any())).thenReturn(true);
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
        when(vcFormatter.getSignatureCryptoSuite(anyString())).thenReturn("testSignatureCryptoSuite"); // Example Value

        when(mockSdJwt.addProof(
                eq("{\"unsigned\":\"sdjwt_payload\"}"), // unsignedCredential
                eq(""),                                 // holderId (now matches due to getKeyMaterial stub)
                anyString(),                            // proofAlgorithm
                anyString(),                            // keyManagerAppId
                anyString(),                            // keyManagerRefId
                anyString(),                             // didUrl
                anyString()
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
    public void getCredential_LedgerStatusDetailAdded_WhenPurposeListAndContextMatch() throws Exception {
        // Arrange
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);
        // Add VCDM2Constants.URL to context to trigger the branch
        request.getCredential_definition().setContext(
                List.of("https://www.w3.org/ns/credentials/v2")
        );

        // Mock credentialFactory and W3CJsonLD
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);

        // Stub getKeyMaterial, its result is used in templateParams for createCredential
        when(proofValidator.getKeyMaterial(any(CredentialProof.class))).thenReturn("");

        when(proofValidator.validate(eq("test-client"), eq(TEST_CNONCE), any(CredentialProof.class), any())).thenReturn(true);
        when(dataProviderPlugin.fetchData(claimsFromAccessToken)).thenReturn(new JSONObject().put("subjectKey", "subjectValue"));

        W3CJsonLD mockW3CJsonLD = mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(DEFAULT_FORMAT_LDP)).thenReturn(Optional.of(mockW3CJsonLD));
        when(mockW3CJsonLD.createCredential(anyMap(), anyString())).thenReturn("{\"unsigned\":\"credential\"}");

        // Stub vcFormatter methods called by service's getVerifiableCredential method for addProof
        when(vcFormatter.getProofAlgorithm(anyString())).thenReturn("EdDSA"); // Example value
        when(vcFormatter.getAppID(anyString())).thenReturn("testAppIdLdp");   // Example value
        when(vcFormatter.getRefID(anyString())).thenReturn("testRefIdLdp");   // Example value
        when(vcFormatter.getDidUrl(anyString())).thenReturn("did:example:ldp"); // Example value
        when(vcFormatter.getSignatureCryptoSuite(anyString())).thenReturn("testSignatureCryptoSuite"); // Example Value
        // Mock credentialStatusPurposeList to be non-empty
        List<String> statusPurposeList = List.of("revocation");
        when(vcFormatter.getCredentialStatusPurpose(anyString())).thenReturn(statusPurposeList);

        // Corrected declaration of mockVcResultLdp
        VCResult mockVcResultLdp = new VCResult<JsonLDObject>();
        JsonLDObject signedCredObj = JsonLDObject.fromJson("{\"signed\":\"credential\", \"proof\":{}}");
        mockVcResultLdp.setCredential(signedCredObj);

        // The holderId argument to addProof in the service is "" for LDP
        when(mockW3CJsonLD.addProof(
                eq("{\"unsigned\":\"credential\"}"),
                eq(""),  // Service code passes "" for LDP's addProof holderId
                anyString(),
                anyString(),
                anyString(),
                anyString(),
                anyString()
        )).thenReturn(mockVcResultLdp);

        CredentialResponse<?> response = issuanceService.getCredential(request);

        assertNotNull("CredentialResponse should not be null", response);
        assertNotNull("Response credential should not be null", response.getCredential());
        assertTrue("Response credential should be JsonLDObject", response.getCredential() instanceof JsonLDObject);

        // Assert
        verify(statusListCredentialService).addCredentialStatus(any(JSONObject.class), eq("revocation"));
    }

    @Test
    public void getCredential_LedgerEntryStored_WhenLedgerEnabled() throws Exception {
        ReflectionTestUtils.setField(issuanceService, "isLedgerEnabled", true);
        // Arrange
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);
        // Add VCDM2Constants.URL to context to trigger the branch
        request.getCredential_definition().setContext(
                List.of("https://www.w3.org/ns/credentials/v2")
        );

        // Mock credentialFactory and W3CJsonLD
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);

        // Stub getKeyMaterial, its result is used in templateParams for createCredential
        when(proofValidator.getKeyMaterial(any(CredentialProof.class))).thenReturn("");

        when(proofValidator.validate(eq("test-client"), eq(TEST_CNONCE), any(CredentialProof.class), any())).thenReturn(true);
        when(dataProviderPlugin.fetchData(claimsFromAccessToken)).thenReturn(new JSONObject().put("subjectKey", "subjectValue"));

        W3CJsonLD mockW3CJsonLD = mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(DEFAULT_FORMAT_LDP)).thenReturn(Optional.of(mockW3CJsonLD));
        when(mockW3CJsonLD.createCredential(anyMap(), anyString())).thenReturn("{\"unsigned\":\"credential\"}");

        // Stub vcFormatter methods called by service's getVerifiableCredential method for addProof
        when(vcFormatter.getProofAlgorithm(anyString())).thenReturn("EdDSA"); // Example value
        when(vcFormatter.getAppID(anyString())).thenReturn("testAppIdLdp");   // Example value
        when(vcFormatter.getRefID(anyString())).thenReturn("testRefIdLdp");   // Example value
        when(vcFormatter.getDidUrl(anyString())).thenReturn("did:example:ldp"); // Example value
        when(vcFormatter.getSignatureCryptoSuite(anyString())).thenReturn("testSignatureCryptoSuite"); // Example Value
        // Mock credentialStatusPurposeList to be non-empty
        List<String> statusPurposeList = List.of("revocation");
        when(vcFormatter.getCredentialStatusPurpose(anyString())).thenReturn(statusPurposeList);
        // Mock ledgerUtils and vcFormatter
        when(ledgerUtils.extractIndexedAttributes(any())).thenReturn(Map.of("attr", "val"));
        when(vcFormatter.getCredentialStatusPurpose(anyString())).thenReturn(statusPurposeList);

        // Corrected declaration of mockVcResultLdp
        VCResult mockVcResultLdp = new VCResult<JsonLDObject>();
        JsonLDObject signedCredObj = JsonLDObject.fromJson("{\"signed\":\"credential\", \"proof\":{}}");
        mockVcResultLdp.setCredential(signedCredObj);

        // The holderId argument to addProof in the service is "" for LDP
        when(mockW3CJsonLD.addProof(
                eq("{\"unsigned\":\"credential\"}"),
                eq(""),  // Service code passes "" for LDP's addProof holderId
                anyString(),
                anyString(),
                anyString(),
                anyString(),
                anyString()
        )).thenReturn(mockVcResultLdp);

        CredentialResponse<?> response = issuanceService.getCredential(request);

        assertNotNull("CredentialResponse should not be null", response);
        assertNotNull("Response credential should not be null", response.getCredential());
        assertTrue("Response credential should be JsonLDObject", response.getCredential() instanceof JsonLDObject);

        // Act
        issuanceService.getCredential(request);
    }
}