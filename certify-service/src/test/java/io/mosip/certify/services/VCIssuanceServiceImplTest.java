package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.VCIExchangeException;
import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.api.spi.VCIssuancePlugin;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.exception.NotAuthenticatedException;
import io.mosip.certify.core.spi.CredentialConfigurationService; // Added import
import io.mosip.certify.core.util.SecurityHelperService;
import io.mosip.certify.enums.CredentialFormat;
import io.mosip.certify.exception.InvalidNonceException;
import io.mosip.certify.proof.ProofValidator;
import io.mosip.certify.proof.ProofValidatorFactory;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;

import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.test.util.ReflectionTestUtils;
import io.mosip.certify.core.constants.Constants;


import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class VCIssuanceServiceImplTest {
    // For testing getCredentialIssuerMetadata
    private LinkedHashMap<String, LinkedHashMap<String, Object>> testIssuerMetadataMap;

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
    CredentialIssuerMetadataVD13DTO mockGlobalCredentialIssuerMetadataDTO;


    @Before
    public void setUp() {
        // MockitoAnnotations.initMocks(this); // Not needed with MockitoJUnitRunner

        testIssuerMetadataMap = new LinkedHashMap<>();
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

        ReflectionTestUtils.setField(issuanceService, "issuerMetadata", testIssuerMetadataMap);
        ReflectionTestUtils.setField(issuanceService, "cNonceExpireSeconds", 300);

        when(parsedAccessToken.getAccessTokenHash()).thenReturn(TEST_ACCESS_TOKEN_HASH);

        claimsFromAccessToken = new HashMap<>();
        claimsFromAccessToken.put("scope", DEFAULT_SCOPE);
        claimsFromAccessToken.put("client_id", "test-client");

        transaction = new VCIssuanceTransaction();
        transaction.setCNonce(TEST_CNONCE);
        transaction.setCNonceExpireSeconds(300);
        transaction.setCNonceIssuedEpoch(LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC));

        // Setup mockGlobalCredentialIssuerMetadataDTO using actual DTO structures
        mockGlobalCredentialIssuerMetadataDTO = new CredentialIssuerMetadataVD13DTO();
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
        // MSO_MDOC might not use credentialDefinition in the same way, or it might be null/empty for this DTO
        // For scope mapping, only format and scope are strictly needed from this DTO for non-LDP types.
        supportedCredsMap.put("test-credential-id-msodoc", supportedDTO_MSODOC);

        // JWT_VC_JSON Config DTO
        CredentialConfigurationSupportedDTO supportedDTO_JWT = new CredentialConfigurationSupportedDTO();
        supportedDTO_JWT.setScope(DEFAULT_SCOPE);
        supportedDTO_JWT.setFormat(VCFormats.JWT_VC_JSON);
        CredentialDefinition credDefDtoJwt = new CredentialDefinition();
        credDefDtoJwt.setContext(List.of("https://www.w3.org/2018/credentials/v1"));
        credDefDtoJwt.setType(List.of("VerifiableCredential", "TestJWTCredential"));
        supportedDTO_JWT.setCredentialDefinition(credDefDtoJwt);
        supportedCredsMap.put("test-credential-id-jwt", supportedDTO_JWT);


        mockGlobalCredentialIssuerMetadataDTO.setCredentialConfigurationSupportedDTO(supportedCredsMap);
        when(credentialConfigurationService.fetchCredentialIssuerMetadata("latest"))
                .thenReturn(mockGlobalCredentialIssuerMetadataDTO);
    }

    private CredentialRequest createValidCredentialRequest(String format) {
        CredentialRequest req = new CredentialRequest();
        req.setFormat(format);

        io.mosip.certify.core.dto.CredentialDefinition requestInnerCredDef = new io.mosip.certify.core.dto.CredentialDefinition();
        if (VCFormats.MSO_MDOC.equals(format)) {
            req.setDoctype("org.iso.18013.5.1.mDL"); // For mso_mdoc
            req.setFormat(VCFormats.MSO_MDOC.toString());
            req.setClaims( Map.ofEntries(Map.entry("claim1","claim2")));
        } else if (VCFormats.SD_JWT.equals(format)) {
            req.setFormat(CredentialFormat.VC_SD_JWT.toString());
            requestInnerCredDef.setContext(List.of("https://www.w3.org/2018/credentials/v1"));
            requestInnerCredDef.setType(List.of("VerifiableCredential", "TestJWTCredential"));
        } else if (VCFormats.JWT_VC_JSON.equals(format)) {
            req.setFormat(CredentialFormat.VC_JWT.toString());
            requestInnerCredDef.setContext(List.of("https://www.w3.org/2018/credentials/v1"));
            requestInnerCredDef.setType(List.of("VerifiableCredential", "TestJWTCredential"));
        } else { // LDP_VC default
            req.setFormat(CredentialFormat.VC_LDP.toString());
            requestInnerCredDef.setContext(List.of("https://www.w3.org/2018/credentials/v1"));
            requestInnerCredDef.setType(List.of("VerifiableCredential", "TestCredential"));
        }
        requestInnerCredDef.setCredentialSubject(new HashMap<>()); // Common for LDP/JWT types
        req.setCredential_definition(requestInnerCredDef);


        CredentialProof proof = new CredentialProof();
        proof.setProof_type("jwt"); // Example proof type
        proof.setJwt("dummy.jwt.token");
        req.setProof(proof);
        return req;
    }

    @Test
    public void getCredential_LDP_WithValidTransaction_Success() throws VCIExchangeException {
        request = createValidCredentialRequest(VCFormats.LDP_VC);
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.validateV2(eq("test-client"), eq(TEST_CNONCE), any(CredentialProof.class), any())).thenReturn(true);
        when(proofValidator.getKeyMaterial(any(CredentialProof.class))).thenReturn(HOLDER_ID);

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
    public void getCredential_ExpiredNonce_ThrowsInvalidNonceException() {
        request = createValidCredentialRequest(VCFormats.LDP_VC);
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
        request = createValidCredentialRequest(VCFormats.LDP_VC);
        Map<String, Object> claimsWithoutCNonce = new HashMap<>(claimsFromAccessToken);
        claimsWithoutCNonce.remove(Constants.C_NONCE);
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
    public void getCredential_LDP_PluginReturnsNullVCResult_Fail() throws VCIExchangeException {
        request = createValidCredentialRequest(VCFormats.LDP_VC);
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.validateV2(anyString(), anyString(), any(CredentialProof.class),any())).thenReturn(true);
        when(proofValidator.getKeyMaterial(any(CredentialProof.class))).thenReturn(HOLDER_ID);
        when(vcIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(any(VCRequestDto.class), eq(HOLDER_ID), eq(claimsFromAccessToken)))
                .thenReturn(null); // Plugin returns null

        CertifyException ex = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals(ErrorConstants.VC_ISSUANCE_FAILED, ex.getErrorCode());
    }

    @Test
    public void getCredential_LDP_PluginReturnsVCResultWithNullCredential_Fail() throws VCIExchangeException {
        request = createValidCredentialRequest(VCFormats.LDP_VC);
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.validateV2(anyString(), anyString(), any(CredentialProof.class),any())).thenReturn(true);
        when(proofValidator.getKeyMaterial(any(CredentialProof.class))).thenReturn(HOLDER_ID);

        VCResult<JsonLDObject> emptyVcResult = new VCResult<>();
        emptyVcResult.setCredential(null); // VCResult has null credential
        when(vcIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(any(VCRequestDto.class), eq(HOLDER_ID), eq(claimsFromAccessToken)))
                .thenReturn(emptyVcResult);

        CertifyException ex = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals(ErrorConstants.VC_ISSUANCE_FAILED, ex.getErrorCode());
    }


    @Test
    public void getCredential_ValidRequest_MsoMDoc_Success() throws VCIExchangeException {
        request = createValidCredentialRequest(VCFormats.MSO_MDOC);
        // request.setDoctype("org.iso.18013.5.1.mDL"); // This is set in createValidCredentialRequest

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.validateV2(anyString(), anyString(), any(CredentialProof.class),any())).thenReturn(true);
        when(proofValidator.getKeyMaterial(any(CredentialProof.class))).thenReturn(HOLDER_ID);

        VCResult<String> msoMDocVCResult = new VCResult<>();
        msoMDocVCResult.setCredential("test_mso_mdoc_credential_string");
        when(vcIssuancePlugin.getVerifiableCredential(any(VCRequestDto.class), eq(HOLDER_ID), eq(claimsFromAccessToken)))
                .thenReturn(msoMDocVCResult);

        CredentialResponse<?> response = issuanceService.getCredential(request);
        assertNotNull(response);
        assertEquals("test_mso_mdoc_credential_string", response.getCredential());
        verify(auditWrapper).logAudit(eq(io.mosip.certify.api.util.Action.VC_ISSUANCE), eq(io.mosip.certify.api.util.ActionStatus.SUCCESS), any(), isNull());
    }

    @Test
    public void getCredential_RequestValidatorFails_ThrowsInvalidRequestException() {
        request = createValidCredentialRequest(VCFormats.LDP_VC);
        request.setFormat("invalid format with spaces"); // Should cause validator to fail

        InvalidRequestException ex = assertThrows(InvalidRequestException.class, () -> issuanceService.getCredential(request));
        assertEquals(ErrorConstants.UNSUPPORTED_VC_FORMAT, ex.getErrorCode());
    }


    @Test
    public void getCredential_InvalidScope_Fail() {
        request = createValidCredentialRequest(VCFormats.LDP_VC);
        Map<String, Object> claimsWithInvalidScope = new HashMap<>(claimsFromAccessToken);
        claimsWithInvalidScope.put("scope", "unknown-scope");

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsWithInvalidScope);
        // mockGlobalCredentialIssuerMetadataDTO in setUp is for DEFAULT_SCOPE. "unknown-scope" won't match.

        CertifyException ex = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals(ErrorConstants.INVALID_SCOPE, ex.getErrorCode());
    }

    @Test
    public void getCredential_InvalidProof_Fail() {
        request = createValidCredentialRequest(VCFormats.LDP_VC);
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claimsFromAccessToken);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(anyString())).thenReturn(proofValidator);
        when(proofValidator.validateV2(anyString(), anyString(), any(CredentialProof.class), any())).thenReturn(false); // Proof fails

        CertifyException ex = assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
        assertEquals(ErrorConstants.INVALID_PROOF, ex.getErrorCode());
    }


    @Test
    public void getCredentialIssuerMetadata_validLatest() {
        Map<String, Object> actual = issuanceService.getCredentialIssuerMetadata("latest");
        assertNotNull(actual);
        assertSame(testIssuerMetadataMap.get("latest"), actual); // Verifies it's from the injected map
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
    public void getCredentialIssuerMetadata_UnsupportedVersion_ThrowsException() {
        InvalidRequestException ex1 = assertThrows(InvalidRequestException.class, () -> issuanceService.getCredentialIssuerMetadata("latestData"));
        assertEquals(ErrorConstants.UNSUPPORTED_OPENID_VERSION, ex1.getErrorCode());

        InvalidRequestException ex2 = assertThrows(InvalidRequestException.class, () -> issuanceService.getCredentialIssuerMetadata(null));
        assertEquals(ErrorConstants.UNSUPPORTED_OPENID_VERSION, ex2.getErrorCode());
    }


    @Test
    public void getCredential_NotAuthenticated_ThrowsException() {
        request = createValidCredentialRequest(VCFormats.LDP_VC);
        when(parsedAccessToken.isActive()).thenReturn(false); // Token not active
        assertThrows(NotAuthenticatedException.class, () -> issuanceService.getCredential(request));
    }

    @Test
    public void getDIDDocument_ThrowsUnsupportedException() {
        InvalidRequestException ex = assertThrows(InvalidRequestException.class, () -> issuanceService.getDIDDocument());
        assertEquals(ErrorConstants.UNSUPPORTED_IN_CURRENT_PLUGIN_MODE, ex.getErrorCode());
    }
}