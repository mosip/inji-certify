package io.mosip.certify.services;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
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
import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.VCIExchangeException;
import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.api.spi.VCIssuancePlugin;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.NonceErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.exception.NotAuthenticatedException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.util.SecurityHelperService;
import io.mosip.certify.proof.ProofValidator;
import io.mosip.certify.proof.ProofValidatorFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.isNull;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class VCIssuanceServiceImplTest {


    @Mock
    private ParsedAccessToken parsedAccessToken;
    @Mock
    private ProofValidatorFactory proofValidatorFactory;
    @Mock
    private VCIssuancePlugin vcIssuancePlugin;
    @Mock
    private VCICacheService vciCacheService;
    @Mock
    private SecurityHelperService securityHelperService;
    @Mock
    private AuditPlugin auditWrapper;
    @Mock
    private ProofValidator proofValidator;
    @Mock
    private CredentialConfigurationService credentialConfigurationService; // Added mock

    @InjectMocks
    private VCIssuanceServiceImpl issuanceService;

    private static final String TEST_ACCESS_TOKEN_HASH = "test-token-hash";
    private static final String TEST_CNONCE = "test-cnonce";
    private static final String DEFAULT_SCOPE = "test-scope";
    private static final String HOLDER_ID = "test_holder_id";


    CredentialRequest request;
    Map<String, Object> claimsFromAccessToken;
    VCIssuanceTransaction transaction;
    CredentialIssuerMetadataDTO mockGlobalCredentialIssuerMetadataDTO;


    @Before
    public void setUp() {
        // MockitoAnnotations.initMocks(this); // Not needed with MockitoJUnitRunner

        LinkedHashMap<String, LinkedHashMap<String, Object>> testIssuerMetadataMap = new LinkedHashMap<>();
        LinkedHashMap<String, Object> latestMetadataConfig = new LinkedHashMap<>();
        LinkedHashMap<String, Object> credentialConfigurationsSupportedForTestMeta = new LinkedHashMap<>();
        LinkedHashMap<String, Object> vcConfigForTestMeta = new LinkedHashMap<>();
        vcConfigForTestMeta.put("format", VCFormats.LDP_VC);
        vcConfigForTestMeta.put("scope", DEFAULT_SCOPE);
        LinkedHashMap<String, Object> credDefMapForTestMeta = new LinkedHashMap<>();
        credDefMapForTestMeta.put("type", Arrays.asList("VerifiableCredential", "TestCredential"));
        vcConfigForTestMeta.put("credential_definition", credDefMapForTestMeta);
        credentialConfigurationsSupportedForTestMeta.put("test-credential-id-meta", vcConfigForTestMeta);
        latestMetadataConfig.put("credential_configurations_supported", credentialConfigurationsSupportedForTestMeta);
        latestMetadataConfig.put("credential_issuer", "https://localhost:9090");
        latestMetadataConfig.put("credential_endpoint", "https://localhost:9090/v1/certify/issuance/credential");
        testIssuerMetadataMap.put("latest", latestMetadataConfig);

        when(parsedAccessToken.getAccessTokenHash()).thenReturn(TEST_ACCESS_TOKEN_HASH);

        claimsFromAccessToken = new HashMap<>();
        claimsFromAccessToken.put("scope", DEFAULT_SCOPE);
        claimsFromAccessToken.put("client_id", "test-client");

        transaction = new VCIssuanceTransaction();
        transaction.setCNonce(TEST_CNONCE);
        transaction.setCNonceExpireSeconds(300);
        transaction.setCNonceIssuedEpoch(LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC));

        // Setup mockGlobalCredentialIssuerMetadataDTO using actual DTO structures
        mockGlobalCredentialIssuerMetadataDTO = new CredentialIssuerMetadataDTO();
        mockGlobalCredentialIssuerMetadataDTO.setNonceEndpoint("https://test.issuer.com/nonce");
        Map<String, CredentialConfigurationSupportedDTO> supportedCredsMap = new HashMap<>();

        // LDP Config DTO
        CredentialConfigurationSupportedDTO supportedDTO_LDP = new CredentialConfigurationSupportedDTO();
        supportedDTO_LDP.setScope(DEFAULT_SCOPE);
        supportedDTO_LDP.setFormat(VCFormats.LDP_VC);
        CredentialDefinition credDefDtoLDP = new CredentialDefinition();
        credDefDtoLDP.setContext(List.of("https://www.w3.org/2018/credentials/v1"));
        credDefDtoLDP.setType(List.of("VerifiableCredential", "TestCredential"));
        supportedDTO_LDP.setCredentialDefinition(credDefDtoLDP);
        supportedCredsMap.put("test-credential-id-ldp", supportedDTO_LDP);

        // MSO_MDOC Config DTO
        CredentialConfigurationSupportedDTO supportedDTO_MSODOC = new CredentialConfigurationSupportedDTO();
        supportedDTO_MSODOC.setScope(DEFAULT_SCOPE); // Assuming same scope for this test
        supportedDTO_MSODOC.setFormat(VCFormats.MSO_MDOC);
        supportedDTO_MSODOC.setDocType("org.iso.18013.5.1.mDL");
        CredentialDefinition credDefDtoForMDOC = new CredentialDefinition();
        credDefDtoForMDOC.setContext(List.of("https://www.w3.org/2018/credentials/v1"));
        credDefDtoForMDOC.setType(List.of("VerifiableCredential", "mDLCredential"));
        supportedDTO_MSODOC.setCredentialDefinition(credDefDtoForMDOC);
        // MSO_MDOC might not use credentialDefinition in the same way, or it might be null/empty for this DTO
        // For scope mapping, only format and scope are strictly needed from this DTO for non-LDP types.
        supportedCredsMap.put("test-credential-id-msodoc", supportedDTO_MSODOC);

        // JWT_VC_JSON Config DTO
        CredentialConfigurationSupportedDTO supportedDTO_JWT = new CredentialConfigurationSupportedDTO();
        supportedDTO_JWT.setScope(DEFAULT_SCOPE);
        CredentialDefinition credDefDtoJwt = new CredentialDefinition();
        credDefDtoJwt.setContext(List.of("https://www.w3.org/2018/credentials/v1"));
        credDefDtoJwt.setType(List.of("VerifiableCredential", "TestJWTCredential"));
        supportedDTO_JWT.setCredentialDefinition(credDefDtoJwt);
        supportedCredsMap.put("test-credential-id-jwt", supportedDTO_JWT);


        mockGlobalCredentialIssuerMetadataDTO.setCredentialConfigurationSupportedDTO(supportedCredsMap);
        when(credentialConfigurationService.fetchCredentialIssuerMetadata())
                .thenReturn(mockGlobalCredentialIssuerMetadataDTO);
    }

    private CredentialRequest createValidCredentialRequest(String format) throws Exception {
        CredentialRequest req = new CredentialRequest();
        if (VCFormats.DC_SD_JWT.equals(format)) {
            req.setCredentialConfigId("test-credential-id-sdjwt");
        } else if(VCFormats.LDP_VC.equals(format)) { // LDP
            req.setCredentialConfigId("test-credential-id-ldp");
        } else if(VCFormats.MSO_MDOC.equals(format)) {
            req.setCredentialConfigId("test-credential-id-msodoc");
        }

        req.setProofs(Map.of(ProofType.JWT,List.of(createValidJWT(TEST_CNONCE, true))));
        return req;
    }

    private String createValidJWT(String cNonce, boolean addNonce) throws Exception {
        // Generate a 2048-bit RSA key pair
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .generate();

        // Extract public key for embedding in the JWT header
        RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(rsaPublicJWK)  // Embed the public JWK
                .build();

        // Build JWT claims
        JWTClaimsSet.Builder jwtClaimsBuilder = new JWTClaimsSet.Builder()
                .audience("test-credential-id")
                .issuer("test-client")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 60000)); // 1 min expiration
        if (addNonce) { // Conditionally add nonce claim
            jwtClaimsBuilder.claim("nonce", cNonce);
        }

        SignedJWT jwt = new SignedJWT(header, jwtClaimsBuilder.build());

        // Sign JWT using private key
        JWSSigner signer = new RSASSASigner(rsaJWK);
        jwt.sign(signer);

        return jwt.serialize();
    }

    private String createValidJWTWithEC(String cNonce, boolean addNonce) throws Exception {

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

        if (addNonce) {
            claimsBuilder.claim("nonce", cNonce);
        }

        SignedJWT jwt = new SignedJWT(header, claimsBuilder.build());

        JWSSigner signer = new ECDSASigner(ecJWK);
        jwt.sign(signer);

        return jwt.serialize();
    }

    @Test
    public void getCredential_LDP_WithValidTransaction_Success() throws Exception {
        request = createValidCredentialRequest(VCFormats.LDP_VC);
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.validate(eq("test-client"), eq(TEST_CNONCE), anyString(), any())).thenReturn(true);
        when(proofValidator.getKeyMaterial(anyString())).thenReturn(HOLDER_ID);

        VCResult<JsonLDObject> vcResultLdp = new VCResult<>();
        JsonLDObject jsonLDObject = new JsonLDObject();
        vcResultLdp.setCredential(jsonLDObject);
        when(vcIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(any(VCRequestDto.class), eq(HOLDER_ID), eq(claimsFromAccessToken)))
                .thenReturn(vcResultLdp);

        CredentialResponse<?> response = issuanceService.getCredential(request);

        assertNotNull(response);
        verify(auditWrapper).logAudit(eq(io.mosip.certify.api.util.Action.VC_ISSUANCE), eq(io.mosip.certify.api.util.ActionStatus.SUCCESS), any(), isNull());
    }

    @Test
    public void getCredential_LDP_WithValidTransaction_Two_Proofs_Success() throws Exception {
        request = createValidCredentialRequest(VCFormats.LDP_VC);
        request.setProofs(Map.of(ProofType.JWT,List.of(createValidJWT(TEST_CNONCE, true),createValidJWTWithEC(TEST_CNONCE, true))));
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.validate(eq("test-client"), eq(TEST_CNONCE), anyString(), any())).thenReturn(true);
        when(proofValidator.getKeyMaterial(anyString())).thenReturn(HOLDER_ID);

        VCResult<JsonLDObject> vcResultLdp = new VCResult<>();
        JsonLDObject jsonLDObject = new JsonLDObject();
        vcResultLdp.setCredential(jsonLDObject);
        when(vcIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(any(VCRequestDto.class), eq(HOLDER_ID), eq(claimsFromAccessToken)))
                .thenReturn(vcResultLdp);

        CredentialResponse<?> response = issuanceService.getCredential(request);
        assertEquals(2,response.getCredentials().size());
        assertNotNull(response);
        verify(auditWrapper).logAudit(eq(io.mosip.certify.api.util.Action.VC_ISSUANCE), eq(io.mosip.certify.api.util.ActionStatus.SUCCESS), any(), isNull());
    }

    @Test
    public void getCredential_LDP_WithValidTransaction_Two_SAME_Proofs_Success() throws Exception {
        request = createValidCredentialRequest(VCFormats.LDP_VC);
        String jwt = createValidJWT(TEST_CNONCE, true);
        request.setProofs(Map.of(ProofType.JWT,List.of(jwt,jwt)));
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.validate(eq("test-client"), eq(TEST_CNONCE), anyString(), any())).thenReturn(true);
        when(proofValidator.getKeyMaterial(anyString())).thenReturn(HOLDER_ID);

        VCResult<JsonLDObject> vcResultLdp = new VCResult<>();
        JsonLDObject jsonLDObject = new JsonLDObject();
        vcResultLdp.setCredential(jsonLDObject);
        when(vcIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(any(VCRequestDto.class), eq(HOLDER_ID), eq(claimsFromAccessToken)))
                .thenReturn(vcResultLdp);

        CredentialResponse<?> response = issuanceService.getCredential(request);
        assertEquals(1,response.getCredentials().size());
        assertNotNull(response);
        verify(auditWrapper).logAudit(eq(io.mosip.certify.api.util.Action.VC_ISSUANCE), eq(io.mosip.certify.api.util.ActionStatus.SUCCESS), any(), isNull());
    }

    @Test
    public void getCredential_ExpiredNonce_ThrowsInvalidNonceException() throws Exception {
        request = createValidCredentialRequest(VCFormats.LDP_VC);
        request.setProofs(Map.of(ProofType.JWT,List.of(createValidJWT("expired-cnonce", true))));

        VCIssuanceTransaction expiredTransaction = new VCIssuanceTransaction();
        expiredTransaction.setCNonce("expired-cnonce");
        expiredTransaction.setCNonceExpireSeconds(10);
        expiredTransaction.setCNonceIssuedEpoch(LocalDateTime.now(ZoneOffset.UTC).minusSeconds(20).toEpochSecond(ZoneOffset.UTC));

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(expiredTransaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);

        CertifyException certifyException = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals(NonceErrorConstants.NONCE_EXPIRED, certifyException.getErrorCode());
    }

    @Test
    public void getCredential_WithNoNonceInProofJwt_Success() throws Exception {
        request = createValidCredentialRequest(VCFormats.LDP_VC);
        request.setProofs(Map.of(ProofType.JWT, List.of(createValidJWT("", false))));
        mockGlobalCredentialIssuerMetadataDTO.setNonceEndpoint(null);

        claimsFromAccessToken.put("iat", LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC));
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.validate(eq("test-client"), eq(null), anyString(), any())).thenReturn(true);
        when(proofValidator.getKeyMaterial(anyString())).thenReturn(HOLDER_ID);

        VCResult<JsonLDObject> vcResultLdp = new VCResult<>();
        JsonLDObject jsonLDObject = new JsonLDObject();
        vcResultLdp.setCredential(jsonLDObject);
        when(vcIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(any(VCRequestDto.class), eq(HOLDER_ID), eq(claimsFromAccessToken)))
                .thenReturn(vcResultLdp);

        CredentialResponse<?> response = issuanceService.getCredential(request);
        assertNotNull(response);
        verify(auditWrapper).logAudit(eq(io.mosip.certify.api.util.Action.VC_ISSUANCE), eq(io.mosip.certify.api.util.ActionStatus.SUCCESS), any(), isNull());
    }

    @Test
    public void getCredential_WithEmptyNonceInProofJwt_ThrowsCertifyException() throws Exception {
        request = createValidCredentialRequest(VCFormats.LDP_VC);
        request.setProofs(Map.of(ProofType.JWT,List.of(createValidJWT("", true))));

        claimsFromAccessToken.put("iat", LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC));
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        CertifyException certifyException = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));

        assertEquals("invalid_proof", certifyException.getErrorCode());
    }

    @Test
    public void getCredential_LDP_PluginReturnsNullVCResult_Fail() throws Exception {
        request = createValidCredentialRequest(VCFormats.LDP_VC);
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.validate(anyString(), anyString(), anyString(),any())).thenReturn(true);
        when(proofValidator.getKeyMaterial(anyString())).thenReturn(HOLDER_ID);
        when(vcIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(any(VCRequestDto.class), eq(HOLDER_ID), eq(claimsFromAccessToken)))
                .thenReturn(null); // Plugin returns null

        CertifyException ex = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals(ErrorConstants.VC_ISSUANCE_FAILED, ex.getErrorCode());
    }

    @Test
    public void getCredential_LDP_PluginReturnsVCResultWithNullCredential_Fail() throws Exception {
        request = createValidCredentialRequest(VCFormats.LDP_VC);
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.validate(anyString(), anyString(), anyString(),any())).thenReturn(true);
        when(proofValidator.getKeyMaterial(anyString())).thenReturn(HOLDER_ID);

        VCResult<JsonLDObject> emptyVcResult = new VCResult<>();
        emptyVcResult.setCredential(null); // VCResult has null credential
        when(vcIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(any(VCRequestDto.class), eq(HOLDER_ID), eq(claimsFromAccessToken)))
                .thenReturn(emptyVcResult);

        CertifyException ex = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals(ErrorConstants.VC_ISSUANCE_FAILED, ex.getErrorCode());
    }


    @Test
    public void getCredential_ValidRequest_MsoMDoc_Success() throws Exception {
        request = createValidCredentialRequest(VCFormats.MSO_MDOC);
        // request.setDoctype("org.iso.18013.5.1.mDL"); // This is set in createValidCredentialRequest

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.validate(anyString(), anyString(), anyString(),any())).thenReturn(true);
        when(proofValidator.getKeyMaterial(anyString())).thenReturn(HOLDER_ID);

        VCResult<String> msoMDocVCResult = new VCResult<>();
        msoMDocVCResult.setCredential("test_mso_mdoc_credential_string");
        when(vcIssuancePlugin.getVerifiableCredential(any(VCRequestDto.class), eq(HOLDER_ID), eq(claimsFromAccessToken)))
                .thenReturn(msoMDocVCResult);

        CredentialResponse<?> response = issuanceService.getCredential(request);
        assertNotNull(response);
        assertEquals("test_mso_mdoc_credential_string", response.getCredentials().getFirst().getCredential());
        verify(auditWrapper).logAudit(eq(io.mosip.certify.api.util.Action.VC_ISSUANCE), eq(io.mosip.certify.api.util.ActionStatus.SUCCESS), any(), isNull());
    }

    @Test
    public void getCredential_ValidRequest_MsoMDoc_Two_Proof_Success() throws Exception {
        request = createValidCredentialRequest(VCFormats.MSO_MDOC);
        request.setProofs(Map.of(ProofType.JWT,List.of(createValidJWT(TEST_CNONCE, true),createValidJWT(TEST_CNONCE, true))));
        // request.setDoctype("org.iso.18013.5.1.mDL"); // This is set in createValidCredentialRequest

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.validate(anyString(), anyString(), anyString(),any())).thenReturn(true);
        when(proofValidator.getKeyMaterial(anyString())).thenReturn(HOLDER_ID);

        VCResult<String> msoMDocVCResult = new VCResult<>();
        msoMDocVCResult.setCredential("test_mso_mdoc_credential_string");
        when(vcIssuancePlugin.getVerifiableCredential(any(VCRequestDto.class), eq(HOLDER_ID), eq(claimsFromAccessToken)))
                .thenReturn(msoMDocVCResult);

        CredentialResponse<?> response = issuanceService.getCredential(request);
        assertNotNull(response);
        assertEquals("test_mso_mdoc_credential_string", response.getCredentials().getFirst().getCredential());
        assertEquals("test_mso_mdoc_credential_string", response.getCredentials().getLast().getCredential());
        verify(auditWrapper).logAudit(eq(io.mosip.certify.api.util.Action.VC_ISSUANCE), eq(io.mosip.certify.api.util.ActionStatus.SUCCESS), any(), isNull());
    }


    @Test
    public void getCredential_InvalidScope_Fail() throws Exception {
        request = createValidCredentialRequest(VCFormats.LDP_VC);
        Map<String, Object> claimsWithInvalidScope = new HashMap<>(claimsFromAccessToken);
        claimsWithInvalidScope.put("scope", "unknown-scope");

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsWithInvalidScope);
        // mockGlobalCredentialIssuerMetadataDTO in setUp is for DEFAULT_SCOPE. "unknown-scope" won't match.

        CertifyException ex = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals(VCIErrorConstants.INVALID_SCOPE, ex.getErrorCode());
    }

    @Test
    public void getCredential_InvalidProof_Fail() throws Exception {
        request = createValidCredentialRequest(VCFormats.LDP_VC);
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.validate(anyString(), anyString(), anyString(), any())).thenReturn(false); // Proof fails

        CertifyException ex = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals(VCIErrorConstants.INVALID_PROOF, ex.getErrorCode());
    }

    @Test
    public void getCredential_NotAuthenticated_ThrowsException() throws Exception {
        request = createValidCredentialRequest(VCFormats.LDP_VC);
        when(parsedAccessToken.isActive()).thenReturn(false); // Token not active
        assertThrows(NotAuthenticatedException.class, () -> issuanceService.getCredential(request));
    }

    @Test
    public void getDIDDocument_ThrowsUnsupportedException() {
        InvalidRequestException ex = assertThrows(InvalidRequestException.class, () -> issuanceService.getDIDDocument());
        assertEquals(ErrorConstants.UNSUPPORTED_IN_CURRENT_PLUGIN_MODE, ex.getErrorCode());
    }

    @Test
    public void getCredential_LDP_WithValidTransaction_throwVciExchangeException() throws Exception {
        request = createValidCredentialRequest(VCFormats.LDP_VC);
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getNonceTransaction(anyString())).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.validate(eq("test-client"), eq(TEST_CNONCE), anyString(), any())).thenReturn(true);
        when(proofValidator.getKeyMaterial(anyString())).thenReturn(HOLDER_ID);

        VCIExchangeException pluginException = new VCIExchangeException("PLUGIN_ERROR_CODE");
        when(vcIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(any(VCRequestDto.class), eq(HOLDER_ID), eq(claimsFromAccessToken)))
                .thenThrow(pluginException);


        CertifyException ex = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals("PLUGIN_ERROR_CODE", ex.getErrorCode());
    }
}