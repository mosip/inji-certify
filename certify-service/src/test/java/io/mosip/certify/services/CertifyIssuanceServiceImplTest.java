package io.mosip.certify.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.api.util.Action;
import io.mosip.certify.api.util.ActionStatus;
import io.mosip.certify.config.VelocityEnvConfig;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.NonceErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.exception.NotAuthenticatedException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.CredentialLedgerService;
import io.mosip.certify.core.util.SecurityHelperService;
import io.mosip.certify.credential.CredentialFactory;
import io.mosip.certify.credential.MDocCredential;
import io.mosip.certify.credential.SDJWT;
import io.mosip.certify.credential.W3CJsonLD;
import io.mosip.certify.proof.ProofValidator;
import io.mosip.certify.proof.ProofValidatorFactory;
import io.mosip.certify.utils.LedgerUtils;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.pixelpass.PixelPass;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
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
    private CredentialConfigurationService credentialConfigurationService;
    @Mock
    private LedgerUtils ledgerUtils;
    @Mock
    private StatusListCredentialService statusListCredentialService;
    @Mock
    private CredentialLedgerService credentialLedgerService;

    @Mock
    private PixelPass pixelPass;

    @Mock
    private VelocityEnvConfig velocityEnvConfig;

    @InjectMocks
    private CertifyIssuanceServiceImpl issuanceService;

    private static final String TEST_ACCESS_TOKEN_HASH = "test-token-hash";
    private static final String TEST_CNONCE = "test-cnonce";
    private static final String DEFAULT_SCOPE = "test-scope";
    private static final String DEFAULT_FORMAT_LDP = VCFormats.LDP_VC;
    private static final String DEFAULT_FORMAT_SDJWT = VCFormats.DC_SD_JWT; // dc+sd-jwt
    private static final String DEFAULT_FORMAT_MDOC = VCFormats.MSO_MDOC; // mso_mdoc

    CredentialRequest request;
    Map<String, Object> claimsFromAccessToken; // Renamed for clarity
    VCIssuanceTransaction transaction;
    CredentialIssuerMetadataDTO mockGlobalCredentialIssuerMetadataDTO;


    @Before
    public void setUp() throws JsonProcessingException {
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
        latestMetadataConfig.put(Constants.CREDENTIAL_CONFIGURATIONS_SUPPORTED, credentialConfigurationsSupportedMapForTestMeta);
        latestMetadataConfig.put("credential_issuer", "https://localhost:9090");
        latestMetadataConfig.put("credential_endpoint", "https://localhost:9090/v1/certify/issuance/credential");
        testIssuerMetadataMap.put("latest", latestMetadataConfig);

        ReflectionTestUtils.setField(issuanceService, "didUrl", "https://test.issuer.com");
        ReflectionTestUtils.setField(issuanceService, "domainUrl", "did:example:ldp");
        ReflectionTestUtils.setField(issuanceService, "ledgerUtils", ledgerUtils);
        ReflectionTestUtils.setField(issuanceService, "statusListCredentialService", statusListCredentialService);
        ReflectionTestUtils.setField(issuanceService, "credentialLedgerService", credentialLedgerService);
        ReflectionTestUtils.setField(issuanceService, "defaultExpiryDuration", "P730D");
        ReflectionTestUtils.setField(issuanceService, "pixelPass", pixelPass);
        ReflectionTestUtils.setField(issuanceService, "velocityEnvConfig", velocityEnvConfig);

        when(parsedAccessToken.getAccessTokenHash()).thenReturn(TEST_ACCESS_TOKEN_HASH);

        claimsFromAccessToken = new HashMap<>();
        claimsFromAccessToken.put("scope", DEFAULT_SCOPE);
        claimsFromAccessToken.put("client_id", "test-client");

        transaction = new VCIssuanceTransaction();
        transaction.setCNonce(TEST_CNONCE);
        transaction.setCNonceExpireSeconds(300);
        transaction.setCNonceIssuedEpoch(LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC));


        mockGlobalCredentialIssuerMetadataDTO = new CredentialIssuerMetadataDTO();
        mockGlobalCredentialIssuerMetadataDTO.setCredentialIssuer("https://test.issuer.com");
        mockGlobalCredentialIssuerMetadataDTO.setAuthorizationServers(List.of("https://auth.server.com"));
        mockGlobalCredentialIssuerMetadataDTO.setCredentialEndpoint("https://test.issuer.com/credentials");
        mockGlobalCredentialIssuerMetadataDTO.setNonceEndpoint("https://test.issuer.com/nonce");

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

        // MSO_MDOC Config DTO
        CredentialConfigurationSupportedDTO supportedDTO_MDOC = new CredentialConfigurationSupportedDTO();
        supportedDTO_MDOC.setScope(DEFAULT_SCOPE); // IMPORTANT: Must match claimsFromAccessToken
        supportedDTO_MDOC.setFormat(DEFAULT_FORMAT_MDOC);
        supportedDTO_MDOC.setDocType("org.iso.18013.5.1.mDL");
        CredentialDefinition credDefDtoForMDOC = new CredentialDefinition();
        credDefDtoForMDOC.setContext(List.of("https://www.w3.org/2018/credentials/v1"));
        credDefDtoForMDOC.setType(List.of("VerifiableCredential", "mDLCredential"));
        supportedDTO_MDOC.setCredentialDefinition(credDefDtoForMDOC);
        supportedCredsMap.put("test-credential-id-mdoc", supportedDTO_MDOC);

        supportedCredsMap.values().forEach(CertifyIssuanceServiceImplTest::requireHolderBinding);
        mockGlobalCredentialIssuerMetadataDTO.setCredentialConfigurationSupportedDTO(supportedCredsMap);

        when(credentialConfigurationService.fetchCredentialIssuerMetadata())
                .thenReturn(mockGlobalCredentialIssuerMetadataDTO); // Default mock
    }

    private static void requireHolderBinding(CredentialConfigurationSupportedDTO dto) {
        dto.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        dto.setProofTypesSupported(Map.of("jwt", Map.of("proof_signing_alg_values_supported", List.of("ES256"))));
    }

    private void removeHolderBinding(String credentialConfigId) {
        CredentialConfigurationSupportedDTO dto = mockGlobalCredentialIssuerMetadataDTO
                .getCredentialConfigurationSupportedDTO().get(credentialConfigId);
        dto.setCryptographicBindingMethodsSupported(null);
        dto.setProofTypesSupported(null);
    }

    private CredentialRequest createValidCredentialRequest(String format) {
        CredentialRequest req = new CredentialRequest();
        if (DEFAULT_FORMAT_SDJWT.equals(format)) {
            req.setCredentialConfigId("test-credential-id-sdjwt");
        } else if(DEFAULT_FORMAT_LDP.equals(format)) { // LDP
            req.setCredentialConfigId("test-credential-id-ldp");
        } else if(DEFAULT_FORMAT_MDOC.equals(format)) {
            req.setCredentialConfigId("test-credential-id-mdoc");
        }

        req.setProofs(Map.of(ProofType.JWT,List.of(createValidJWT(TEST_CNONCE))));
        return req;
    }

    private String createValidJWT(String nonce) {
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
            Map<String, Object> pj = Map.of("aud", "fake-aud", "nonce", nonce, "iss", "test-client");
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
        return requestProofJWT.serialize();
    }

    private String createValidJWTWithEC(String cNonce) throws Exception {

        // Generate EC key (P-256 curve)
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyID(UUID.randomUUID().toString())
                .generate();

        ECKey ecPublicJWK = ecJWK.toPublicJWK();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(ecPublicJWK)
                .build();

        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .audience("test-credential-id")
                .issuer("test-client")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 60000));

        claimsBuilder.claim("nonce", cNonce);

        SignedJWT jwt = new SignedJWT(header, claimsBuilder.build());

        JWSSigner signer = new ECDSASigner(ecJWK);
        jwt.sign(signer);

        return jwt.serialize();
    }

    @Test
    public void getCredential_LDP_WithValidTransaction_Success() throws DataProviderExchangeException {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);

        // Stub getKeyMaterial, its result is used in templateParams for createCredential
        when(proofValidator.getKeyMaterial(anyString())).thenReturn("");

        when(proofValidator.validate(eq("test-client"), eq(TEST_CNONCE), anyString(), any())).thenReturn(true);
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
        assertNotNull("Response credential should not be null", response.getCredentials());
        assertTrue("Response credential should be JsonLDObject", response.getCredentials().getFirst().getCredential() instanceof JsonLDObject);
        // Refined audit log matcher
        verify(auditWrapper).logAudit(eq(Action.VC_ISSUANCE), eq(ActionStatus.SUCCESS), any(), isNull());
    }

    @Test
    public void getCredential_LDP_WithValidTransaction_With_TwoProofs_Success() throws Exception {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);
        request.setProofs(Map.of(ProofType.JWT,List.of(createValidJWT(TEST_CNONCE), createValidJWTWithEC(TEST_CNONCE))));

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(credentialConfigurationService.fetchCredentialIssuerMetadata()).thenReturn(mockGlobalCredentialIssuerMetadataDTO);

        // Stub getKeyMaterial, its result is used in templateParams for createCredential
        when(proofValidator.getKeyMaterial(anyString())).thenReturn("");

        when(proofValidator.validate(eq("test-client"), eq(TEST_CNONCE), anyString(), any())).thenReturn(true);
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
        assertNotNull("Response credential should not be null", response.getCredentials());
        assertEquals(2,response.getCredentials().size());
        assertTrue("Response credential should be JsonLDObject", response.getCredentials().getFirst().getCredential() instanceof JsonLDObject);
        assertTrue("Response credential should be JsonLDObject", response.getCredentials().getLast().getCredential() instanceof JsonLDObject);
        // Refined audit log matcher
        verify(auditWrapper).logAudit(eq(Action.VC_ISSUANCE), eq(ActionStatus.SUCCESS), any(), isNull());
    }

    @Test
    public void getCredential_LDP_WithValidTransaction_With_Two_SAME_Proofs_Success() throws DataProviderExchangeException {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);
        String jwt = createValidJWT(TEST_CNONCE);
        request.setProofs(Map.of(ProofType.JWT,List.of(jwt, jwt)));

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(credentialConfigurationService.fetchCredentialIssuerMetadata()).thenReturn(mockGlobalCredentialIssuerMetadataDTO);

        // Stub getKeyMaterial, its result is used in templateParams for createCredential
        when(proofValidator.getKeyMaterial(anyString())).thenReturn("");

        when(proofValidator.validate(eq("test-client"), eq(TEST_CNONCE), anyString(), any())).thenReturn(true);
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
        assertNotNull("Response credential should not be null", response.getCredentials());
        assertEquals(1,response.getCredentials().size());
        assertTrue("Response credential should be JsonLDObject", response.getCredentials().getFirst().getCredential() instanceof JsonLDObject);
        // Refined audit log matcher
        verify(auditWrapper).logAudit(eq(Action.VC_ISSUANCE), eq(ActionStatus.SUCCESS), any(), isNull());
    }

    @Test
    public void getCredential_UnsupportedFormatHandledByFactory_Fail() throws DataProviderExchangeException {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.validate(anyString(), anyString(), anyString(),any())).thenReturn(true);
        when(dataProviderPlugin.fetchData(anyMap())).thenReturn(new JSONObject());
        when(proofValidator.getKeyMaterial(anyString())).thenReturn("did:example:holder123");
        when(credentialConfigurationService.fetchCredentialIssuerMetadata()).thenReturn(mockGlobalCredentialIssuerMetadataDTO);
        when(credentialFactory.getCredential(DEFAULT_FORMAT_LDP)).thenReturn(Optional.empty());

        CertifyException ex = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals("unsupported_credential_format", ex.getErrorCode());
    }

    @Test
    public void getCredential_ValidRequest_DataProviderException_Fail() throws DataProviderExchangeException {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.getKeyMaterial(anyString())).thenReturn("did:example:holder123");
        when(proofValidator.validate(anyString(), anyString(), anyString(),any())).thenReturn(true);
        DataProviderExchangeException e = new DataProviderExchangeException("DP_FETCH_FAILED", "Failed to fetch data");
        when(dataProviderPlugin.fetchData(claimsFromAccessToken)).thenThrow(e);

        CertifyException ex = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals("DP_FETCH_FAILED", ex.getErrorCode());
    }

    @Test
    public void getCredential_ExpiredNonce_ThrowsInvalidNonceException() {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);
        request.setProofs(Map.of(ProofType.JWT,List.of(createValidJWT("expired-cnonce"))));

        VCIssuanceTransaction expiredTransaction = new VCIssuanceTransaction();
        expiredTransaction.setCNonce("expired-cnonce");
        expiredTransaction.setCNonceExpireSeconds(10);
        expiredTransaction.setCNonceIssuedEpoch(LocalDateTime.now(ZoneOffset.UTC).minusSeconds(20).toEpochSecond(ZoneOffset.UTC));

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(expiredTransaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);

        CertifyException ex = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals(NonceErrorConstants.NONCE_EXPIRED, ex.getErrorCode());
    }

    @Test
    public void getCredential_NonceInProofJwtButNotInCache_ThrowsCertifyException() {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);
        Map<String, Object> claimsWithoutCNonce = new HashMap<>(claimsFromAccessToken);

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsWithoutCNonce);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(null);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        CertifyException certifyException = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals(NonceErrorConstants.INVALID_NONCE, certifyException.getErrorCode());
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
        assertEquals(VCIErrorConstants.INVALID_SCOPE, ex.getErrorCode());
    }

    @Test
    public void getCredential_InvalidProof_Fail() {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.validate(anyString(), anyString(), anyString(),any())).thenReturn(false);

        CertifyException ex = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals(VCIErrorConstants.INVALID_PROOF, ex.getErrorCode());
    }

    @Test
    public void getVerifiableCredential_NotAuthenticated_ThrowsNotAuthenticatedException() {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);
        when(parsedAccessToken.isActive()).thenReturn(false);
        assertThrows(NotAuthenticatedException.class, () -> issuanceService.getCredential(request));
    }

    @Test
    public void getCredential_HolderBindingNotRequired_SkipsProofValidation_Success() throws DataProviderExchangeException {
        request = new CredentialRequest();
        request.setCredentialConfigId("test-credential-id-ldp");
        request.setProofs(null); // no proofs submitted; holder binding not required

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        removeHolderBinding("test-credential-id-ldp");

        when(dataProviderPlugin.fetchData(claimsFromAccessToken)).thenReturn(new JSONObject().put("subjectKey", "subjectValue"));

        W3CJsonLD mockW3CJsonLD = mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(DEFAULT_FORMAT_LDP)).thenReturn(Optional.of(mockW3CJsonLD));
        when(mockW3CJsonLD.createCredential(anyMap(), anyString())).thenReturn("{\"unsigned\":\"credential\"}");

        when(vcFormatter.getProofAlgorithm(anyString())).thenReturn("EdDSA");
        when(vcFormatter.getAppID(anyString())).thenReturn("testAppIdLdp");
        when(vcFormatter.getRefID(anyString())).thenReturn("testRefIdLdp");
        when(vcFormatter.getDidUrl(anyString())).thenReturn("did:example:ldp");
        when(vcFormatter.getSignatureCryptoSuite(anyString())).thenReturn("testSignatureCryptoSuite");

        VCResult mockVcResultLdp = new VCResult<JsonLDObject>();
        JsonLDObject signedCredObj = JsonLDObject.fromJson("{\"signed\":\"credential\", \"proof\":{}}");
        mockVcResultLdp.setCredential(signedCredObj);

        // holderId is null here (no proof validation ran); the service still passes "" to addProof for LDP.
        when(mockW3CJsonLD.addProof(
                eq("{\"unsigned\":\"credential\"}"),
                eq(""),
                anyString(),
                anyString(),
                anyString(),
                anyString(),
                anyString()
        )).thenReturn(mockVcResultLdp);

        CredentialResponse<?> response = issuanceService.getCredential(request);

        assertNotNull(response);
        assertTrue(response.getCredentials().getFirst().getCredential() instanceof JsonLDObject);
        verifyNoInteractions(proofValidatorFactory, proofValidator);
        verify(auditWrapper).logAudit(eq(Action.VC_ISSUANCE), eq(ActionStatus.SUCCESS), any(), isNull());
    }

    @Test
    public void getCredential_HolderBindingRequired_MissingProofs_ThrowsInvalidProof() {
        request = new CredentialRequest();
        request.setCredentialConfigId("test-credential-id-ldp");
        request.setProofs(Collections.emptyMap()); // holder binding required (default stub), but no proofs submitted

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);

        CertifyException ex = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals(VCIErrorConstants.INVALID_PROOF, ex.getErrorCode());
        verifyNoInteractions(proofValidatorFactory);
    }

    @Test
    public void getCredential_MsoMdocWithoutBindingMetadata_StillRequiresProof() {
        removeHolderBinding("test-credential-id-mdoc");
        request = new CredentialRequest();
        request.setCredentialConfigId("test-credential-id-mdoc");
        request.setProofs(null);

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);

        CertifyException ex = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals(VCIErrorConstants.INVALID_PROOF, ex.getErrorCode());
        verifyNoInteractions(proofValidatorFactory);
    }

    @Test
    public void getCredential_SDJWT_Success() throws Exception {
        request = createValidCredentialRequest(DEFAULT_FORMAT_SDJWT);

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);

        // Crucial: Stub getKeyMaterial to return "" to match the addProof mock
        when(proofValidator.getKeyMaterial(anyString())).thenReturn("");

        when(proofValidator.validate(anyString(), eq(TEST_CNONCE), anyString(), any())).thenReturn(true);
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
        assertNotNull("Response credential should not be null", response.getCredentials());
        assertTrue("Response credential should be a String", response.getCredentials().getFirst().getCredential() instanceof String);
        String credential = (String) response.getCredentials().getFirst().getCredential();
        assertTrue("Credential string should contain SD-JWT disclosure separator '~'", credential.contains("~"));
        verify(auditWrapper).logAudit(eq(Action.VC_ISSUANCE), eq(ActionStatus.SUCCESS), any(), isNull());
    }

    @Test
    public void getCredential_SDJWT_HolderBindingRequired_CnfClaimReflectsHolderId() throws Exception {
        request = createValidCredentialRequest(DEFAULT_FORMAT_SDJWT);
        String expectedHolderId = "did:jwk:test-holder-sdjwt";

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.getKeyMaterial(anyString())).thenReturn(expectedHolderId);
        when(proofValidator.validate(anyString(), eq(TEST_CNONCE), anyString(), any())).thenReturn(true);
        when(dataProviderPlugin.fetchData(claimsFromAccessToken)).thenReturn(new JSONObject().put("key", "value"));

        SDJWT mockSdJwt = mock(SDJWT.class);
        when(credentialFactory.getCredential(DEFAULT_FORMAT_SDJWT)).thenReturn(Optional.of(mockSdJwt));
        when(mockSdJwt.createCredential(anyMap(), anyString())).thenReturn("{\"unsigned\":\"sdjwt_payload\"}");

        VCResult mockVcResultSdJwt = new VCResult<String>();
        mockVcResultSdJwt.setCredential("signed.sdjwt.string~disclosure1~disclosure2");

        when(vcFormatter.getProofAlgorithm(anyString())).thenReturn("EdDSA");
        when(vcFormatter.getAppID(anyString())).thenReturn("testAppId");
        when(vcFormatter.getRefID(anyString())).thenReturn("testRefId");
        when(vcFormatter.getDidUrl(anyString())).thenReturn("did:example:123");
        when(vcFormatter.getSignatureCryptoSuite(anyString())).thenReturn("testSignatureCryptoSuite");

        when(mockSdJwt.addProof(anyString(), eq(""), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(mockVcResultSdJwt);

        issuanceService.getCredential(request);

        ArgumentCaptor<Map> templateParamsCaptor = ArgumentCaptor.forClass(Map.class);
        verify(mockSdJwt).createCredential(templateParamsCaptor.capture(), anyString());
        Map<String, Object> capturedTemplateParams = templateParamsCaptor.getValue();

        assertTrue("cnf claim must be present when holder binding is required and a proof was validated",
                capturedTemplateParams.containsKey(Constants.CONFIRMATION));
        Object cnf = capturedTemplateParams.get(Constants.CONFIRMATION);
        String kid = (cnf instanceof JSONObject)
                ? ((JSONObject) cnf).getString("kid")
                : ((Map<?, ?>) cnf).get("kid").toString();
        assertEquals(expectedHolderId, kid);
    }

    @Test
    public void getCredential_SDJWT_HolderBindingNotRequired_SkipsProofValidation_Success() throws Exception {
        request = new CredentialRequest();
        request.setCredentialConfigId("test-credential-id-sdjwt");
        request.setProofs(null); // no proofs submitted; holder binding not required

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        removeHolderBinding("test-credential-id-sdjwt");
        when(dataProviderPlugin.fetchData(claimsFromAccessToken)).thenReturn(new JSONObject().put("key", "value"));

        SDJWT mockSdJwt = mock(SDJWT.class);
        when(credentialFactory.getCredential(DEFAULT_FORMAT_SDJWT)).thenReturn(Optional.of(mockSdJwt));
        when(mockSdJwt.createCredential(anyMap(), anyString())).thenReturn("{\"unsigned\":\"sdjwt_payload\"}");

        VCResult mockVcResultSdJwt = new VCResult<String>();
        mockVcResultSdJwt.setCredential("signed.sdjwt.string~disclosure1~disclosure2");

        when(vcFormatter.getProofAlgorithm(anyString())).thenReturn("EdDSA");
        when(vcFormatter.getAppID(anyString())).thenReturn("testAppId");
        when(vcFormatter.getRefID(anyString())).thenReturn("testRefId");
        when(vcFormatter.getDidUrl(anyString())).thenReturn("did:example:123");
        when(vcFormatter.getSignatureCryptoSuite(anyString())).thenReturn("testSignatureCryptoSuite");

        when(mockSdJwt.addProof(anyString(), eq(""), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(mockVcResultSdJwt);

        CredentialResponse<?> response = issuanceService.getCredential(request);

        assertNotNull(response);
        assertTrue(response.getCredentials().getFirst().getCredential() instanceof String);
        verifyNoInteractions(proofValidatorFactory, proofValidator);

        ArgumentCaptor<Map> templateParamsCaptor = ArgumentCaptor.forClass(Map.class);
        verify(mockSdJwt).createCredential(templateParamsCaptor.capture(), anyString());
        assertFalse("cnf claim must not be present when holder binding is not required",
                templateParamsCaptor.getValue().containsKey(Constants.CONFIRMATION));
        verify(auditWrapper).logAudit(eq(Action.VC_ISSUANCE), eq(ActionStatus.SUCCESS), any(), isNull());
    }

    @Test
    public void getCredential_SDJWT_With_TWO_PROOFS_Success() throws Exception {
        request = createValidCredentialRequest(DEFAULT_FORMAT_SDJWT);
        request.setProofs(Map.of(ProofType.JWT,List.of(createValidJWT(TEST_CNONCE), createValidJWTWithEC(TEST_CNONCE))));


        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);

        // Crucial: Stub getKeyMaterial to return "" to match the addProof mock
        when(proofValidator.getKeyMaterial(anyString())).thenReturn("");

        when(proofValidator.validate(anyString(), eq(TEST_CNONCE), anyString(), any())).thenReturn(true);
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
        assertNotNull("Response credential should not be null", response.getCredentials());
        assertTrue("Response credential should be a String", response.getCredentials().getFirst().getCredential() instanceof String);
        assertTrue("Response credential should be a String", response.getCredentials().getLast().getCredential() instanceof String);
        String credential1 = (String) response.getCredentials().getFirst().getCredential();
        assertTrue("Credential string should contain SD-JWT disclosure separator '~'", credential1.contains("~"));
        String credential2 = (String) response.getCredentials().getLast().getCredential();
        assertTrue("Credential string should contain SD-JWT disclosure separator '~'", credential2.contains("~"));
        assertEquals(2,response.getCredentials().size());
        verify(auditWrapper).logAudit(eq(Action.VC_ISSUANCE), eq(ActionStatus.SUCCESS), any(), isNull());
    }

    @Test
    public void getCredential_SDJWT_With_TWO_SAME_PROOFS_Success() throws Exception {
        request = createValidCredentialRequest(DEFAULT_FORMAT_SDJWT);
        String jwt = createValidJWT(TEST_CNONCE);
        request.setProofs(Map.of(ProofType.JWT,List.of(jwt, jwt)));


        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);

        // Crucial: Stub getKeyMaterial to return "" to match the addProof mock
        when(proofValidator.getKeyMaterial(anyString())).thenReturn("");

        when(proofValidator.validate(anyString(), eq(TEST_CNONCE), anyString(), any())).thenReturn(true);
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
        assertNotNull("Response credential should not be null", response.getCredentials());
        assertTrue("Response credential should be a String", response.getCredentials().getFirst().getCredential() instanceof String);
        assertTrue("Response credential should be a String", response.getCredentials().getLast().getCredential() instanceof String);
        String credential1 = (String) response.getCredentials().getFirst().getCredential();
        assertTrue("Credential string should contain SD-JWT disclosure separator '~'", credential1.contains("~"));
        assertEquals(1,response.getCredentials().size());
        verify(auditWrapper).logAudit(eq(Action.VC_ISSUANCE), eq(ActionStatus.SUCCESS), any(), isNull());
    }

    @Test
    public void getCredential_LedgerStatusDetailAdded_WhenPurposeListAndContextMatch() throws Exception {
        // Arrange
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);
        request.setCredentialConfigId("test-credential-id-ldp-dm-2.0");

        // Mock credentialFactory and W3CJsonLD
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);

        // Stub getKeyMaterial, its result is used in templateParams for createCredential
        when(proofValidator.getKeyMaterial(anyString())).thenReturn("");

        when(proofValidator.validate(eq("test-client"), eq(TEST_CNONCE), anyString(), any())).thenReturn(true);
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
        assertNotNull("Response credential should not be null", response.getCredentials().getFirst().getCredential());
        assertTrue("Response credential should be JsonLDObject", response.getCredentials().getFirst().getCredential() instanceof JsonLDObject);

        // Assert
        verify(statusListCredentialService).addCredentialStatus(any(JSONObject.class), eq("revocation"));
    }

    @Test
    public void getCredential_LedgerEntryStored_WhenLedgerEnabled() throws Exception {
        ReflectionTestUtils.setField(issuanceService, "isLedgerEnabled", true);
        // Arrange
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);

        // Mock credentialFactory and W3CJsonLD
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);

        // Stub getKeyMaterial, its result is used in templateParams for createCredential
        when(proofValidator.getKeyMaterial(anyString())).thenReturn("");

        when(proofValidator.validate(eq("test-client"), eq(TEST_CNONCE), anyString(), any())).thenReturn(true);
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
        assertNotNull("Response credential should not be null", response.getCredentials());
        assertTrue("Response credential should be JsonLDObject", response.getCredentials().getFirst().getCredential() instanceof JsonLDObject);

        // Act
        issuanceService.getCredential(request);
        verify(credentialLedgerService, atLeastOnce()).storeLedgerEntry(
                isNull(), anyString(), anyString(), isNull(), anyMap(), any(LocalDateTime.class)
        );
    }

    @Test
    public void getCredential_MDOC_Success() throws Exception {
        // Create MDOC request with matching doctype
        request = createValidCredentialRequest(DEFAULT_FORMAT_MDOC);

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);

        // Stub getKeyMaterial to return ""
        when(proofValidator.getKeyMaterial(anyString())).thenReturn("");

        when(proofValidator.validate(eq("test-client"), eq(TEST_CNONCE), anyString(), any())).thenReturn(true);
        when(dataProviderPlugin.fetchData(claimsFromAccessToken)).thenReturn(new JSONObject().put("key", "value"));

        // Mock the mDOC credential
        MDocCredential mockMdoc = mock(MDocCredential.class);
        when(credentialFactory.getCredential(DEFAULT_FORMAT_MDOC)).thenReturn(Optional.of(mockMdoc));
        when(mockMdoc.createCredential(anyMap(), anyString())).thenReturn("unsigned_mdoc_data");

        VCResult mockVcResultMdoc = new VCResult<String>();
        mockVcResultMdoc.setCredential("signed.mdoc.credential.data");

        // Stub vcFormatter methods
        when(vcFormatter.getProofAlgorithm(anyString())).thenReturn("ES256");
        when(vcFormatter.getAppID(anyString())).thenReturn("testAppIdMdoc");
        when(vcFormatter.getRefID(anyString())).thenReturn("testRefIdMdoc");
        when(vcFormatter.getDidUrl(anyString())).thenReturn("did:example:mdoc");
        when(vcFormatter.getSignatureCryptoSuite(anyString())).thenReturn("testSignatureCryptoSuite");

        when(mockMdoc.addProof(
                eq("unsigned_mdoc_data"),
                eq(""),
                anyString(),
                anyString(),
                anyString(),
                anyString(),
                anyString()
        )).thenReturn(mockVcResultMdoc);

        CredentialResponse<?> response = issuanceService.getCredential(request);

        assertNotNull("CredentialResponse should not be null", response);
        assertNotNull("Response credential should not be null", response.getCredentials());
        assertTrue("Response credential should be a String", response.getCredentials().getFirst().getCredential() instanceof String);
        String credential = (String) response.getCredentials().getFirst().getCredential();
        assertEquals("signed.mdoc.credential.data", credential);
        verify(auditWrapper).logAudit(eq(Action.VC_ISSUANCE), eq(ActionStatus.SUCCESS), any(), isNull());
    }

    @Test
    public void getCredential_QRDataPresent_Claim169ValuesAdded() throws Exception {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.getKeyMaterial(anyString())).thenReturn("");
        when(proofValidator.validate(anyString(), anyString(), anyString(), any())).thenReturn(true);
        when(dataProviderPlugin.fetchData(claimsFromAccessToken)).thenReturn(new JSONObject().put("subjectKey", "subjectValue"));

        // Mock credential and QR data
        W3CJsonLD mockW3CJsonLD = mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(DEFAULT_FORMAT_LDP)).thenReturn(Optional.of(mockW3CJsonLD));
        when(mockW3CJsonLD.createCredential(anyMap(), anyString())).thenReturn("{\"unsigned\":\"credential\"}");

        // Prepare a non-empty QR data array
        JSONArray qrData = new JSONArray();
        JSONObject qrData1 = new JSONObject().put("qr", "data1");
        qrData.put(qrData1);
        JSONObject qrData2 = new JSONObject().put("qr", "data2");
        qrData.put(qrData2);
        when(mockW3CJsonLD.createQRData(anyMap(), anyString())).thenReturn(qrData);

        Object mappedData1 = "mappedData1";
        Object mappedData2 = "mappedData2";
        when(pixelPass.getMappedData(eq(qrData1), anyMap(), anyMap(), eq(true))).thenReturn(mappedData1);
        when(pixelPass.getMappedData(eq(qrData2), anyMap(), anyMap(), eq(true))).thenReturn(mappedData2);

        // Mock signQRData to return signed QR strings
        when(mockW3CJsonLD.signQRData(eq("mappedData1"), anyString(), anyString(), anyString(), anyString()))
                .thenReturn("signedQR1");
        when(mockW3CJsonLD.signQRData(eq("mappedData2"), anyString(), anyString(), anyString(), anyString()))
                .thenReturn("signedQR2");

        when(pixelPass.generateQRData(eq("signedQR1"), eq(""))).thenReturn("qrCodeData1");
        when(pixelPass.generateQRData(eq("signedQR2"), eq(""))).thenReturn("qrCodeData2");
        // Usual formatter mocks
        when(vcFormatter.getProofAlgorithm(anyString())).thenReturn("EdDSA");
        when(vcFormatter.getAppID(anyString())).thenReturn("testAppIdLdp");
        when(vcFormatter.getRefID(anyString())).thenReturn("testRefIdLdp");
        when(vcFormatter.getDidUrl(anyString())).thenReturn("did:example:ldp");
        when(vcFormatter.getSignatureCryptoSuite(anyString())).thenReturn("testSignatureCryptoSuite");

        VCResult mockVcResultLdp = new VCResult<JsonLDObject>();
        JsonLDObject signedCredObj = JsonLDObject.fromJson("{\"signed\":\"credential\", \"proof\":{}}");
        mockVcResultLdp.setCredential(signedCredObj);

        when(mockW3CJsonLD.addProof(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(mockVcResultLdp);

        CredentialResponse<?> response = issuanceService.getCredential(request);

        assertNotNull(response);
        assertNotNull(response.getCredentials());
        // Check that claim_169_values is present and contains the signed QR codes
        ArgumentCaptor<Map<String, Object>> templateParamsCaptor = ArgumentCaptor.forClass(Map.class);
        verify(mockW3CJsonLD).createCredential(templateParamsCaptor.capture(), anyString());
        Map<String, Object> usedParams = templateParamsCaptor.getValue();
        assertTrue(usedParams.containsKey("claim_169_values"));
        List<String> claim169Values = (List<String>) usedParams.get("claim_169_values");
        assertEquals(2, claim169Values.size());
        assertTrue(claim169Values.contains("qrCodeData1"));
        assertTrue(claim169Values.contains("qrCodeData2"));
    }

    @Test
    public void getCredential_QRDataNull_LogsWarning() throws Exception {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.getKeyMaterial(anyString())).thenReturn("");
        when(proofValidator.validate(anyString(), anyString(), anyString(), any())).thenReturn(true);
        when(dataProviderPlugin.fetchData(claimsFromAccessToken)).thenReturn(new JSONObject().put("subjectKey", "subjectValue"));

        W3CJsonLD mockW3CJsonLD = mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(DEFAULT_FORMAT_LDP)).thenReturn(Optional.of(mockW3CJsonLD));
        when(mockW3CJsonLD.createCredential(anyMap(), anyString())).thenReturn("{\"unsigned\":\"credential\"}");
        // Return null for QR data
        when(mockW3CJsonLD.createQRData(anyMap(), anyString())).thenReturn(null);

        when(vcFormatter.getProofAlgorithm(anyString())).thenReturn("EdDSA");
        when(vcFormatter.getAppID(anyString())).thenReturn("testAppIdLdp");
        when(vcFormatter.getRefID(anyString())).thenReturn("testRefIdLdp");
        when(vcFormatter.getDidUrl(anyString())).thenReturn("did:example:ldp");
        when(vcFormatter.getSignatureCryptoSuite(anyString())).thenReturn("testSignatureCryptoSuite");

        VCResult mockVcResultLdp = new VCResult<JsonLDObject>();
        JsonLDObject signedCredObj = JsonLDObject.fromJson("{\"signed\":\"credential\", \"proof\":{}}");
        mockVcResultLdp.setCredential(signedCredObj);

        when(mockW3CJsonLD.addProof(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(mockVcResultLdp);

        // You may want to use a log capturing library to assert the warning log, but here we just ensure no exception
        CredentialResponse<?> response = issuanceService.getCredential(request);

        assertNotNull(response);
        assertNotNull(response.getCredentials());
        // Optionally, verify that claim_169_values is not present
        ArgumentCaptor<Map<String, Object>> templateParamsCaptor = ArgumentCaptor.forClass(Map.class);
        verify(mockW3CJsonLD).createCredential(templateParamsCaptor.capture(), anyString());
        Map<String, Object> usedParams = templateParamsCaptor.getValue();
        assertFalse(usedParams.containsKey("claim_169_values"));
    }

    @Test
    public void getCredential_ErrorSigningQRData_ThrowsCertifyException() throws Exception {
        request = createValidCredentialRequest(DEFAULT_FORMAT_LDP);

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.getKeyMaterial(anyString())).thenReturn("");
        when(proofValidator.validate(anyString(), anyString(), anyString(), any())).thenReturn(true);
        when(dataProviderPlugin.fetchData(claimsFromAccessToken)).thenReturn(new JSONObject().put("subjectKey", "subjectValue"));

        // Mock credential and QR data
        W3CJsonLD mockW3CJsonLD = mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(DEFAULT_FORMAT_LDP)).thenReturn(Optional.of(mockW3CJsonLD));

        // Prepare a non-empty QR data array
        JSONArray qrData = new JSONArray();
        JSONObject qrData1 = new JSONObject().put("qr", "data1");
        qrData.put(qrData1);
        when(mockW3CJsonLD.createQRData(anyMap(), anyString())).thenReturn(qrData);

        when(pixelPass.getMappedData(eq(qrData1), anyMap(), anyMap(), eq(true))).thenThrow(new RuntimeException("Error during signing QR data"));

        CertifyException ex = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals("error_signing_qr_data", ex.getErrorCode());
        assertEquals("Error during signing QR data", ex.getMessage());
    }

}