package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.api.exception.VCIExchangeException;
import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.credential.Credential;
import io.mosip.certify.credential.CredentialFactory;
import io.mosip.certify.credential.SDJWT;
import io.mosip.certify.credential.W3cJsonLd;
import io.mosip.certify.exception.InvalidNonceException;
import io.mosip.certify.proof.ProofValidator;
import io.mosip.certify.proofgenerators.ProofGenerator;
import io.mosip.certify.utils.DIDDocumentUtil;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.exception.NotAuthenticatedException;
import io.mosip.certify.core.util.SecurityHelperService;
import io.mosip.certify.proof.ProofValidatorFactory;
import io.mosip.certify.vcsigners.VCSigner;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.service.SignatureService;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;

import static io.mosip.certify.core.constants.ErrorConstants.UNSUPPORTED_VC_FORMAT;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
@ConditionalOnProperty(value = "mosip.certify.plugin-mode", havingValue = "DataProvider")
public class CertifyIssuanceServiceImplTest {

    @Mock
    private LinkedHashMap<String, LinkedHashMap<String, Object>> issuerMetadata;

    @Mock
    private ParsedAccessToken parsedAccessToken;

    @Mock
    private VCFormatter vcFormatter;

    @Mock
    private VCSigner vcSigner;

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
    private SignatureService signatureService;

    @InjectMocks
    private CertifyIssuanceServiceImpl issuanceService;

    @Mock
    private CredentialFactory credentialFactory;

    @Mock
    private ProofGenerator proofGenerator;

    @Mock
    private KeymanagerService keymanagerService;

    private static final String TEST_ACCESS_TOKEN_HASH = "test-token-hash";
    private static final String TEST_CNONCE = "test-cnonce";

    CredentialRequest request;
    VCResult<JsonLDObject> vcResult;
    Map<String, Object> claims;
    VCIssuanceTransaction transaction;

    private static final String ISSUER_URI = "http://example.com/issuer";
    private static final String ISSUER_PUBLIC_KEY_URI = "http://example.com/issuer#key-1";
    private static final String VC_SIGN_ALGORITHM = SignatureAlg.ED25519_SIGNATURE_SUITE_2020;
    private static final String CERTIFICATE_STRING = "dummy-certificate";

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);

        issuerMetadata = new LinkedHashMap<>();
        LinkedHashMap<String, Object> latestMetadata = new LinkedHashMap<>();
        LinkedHashMap<String, Object> credentialConfig = new LinkedHashMap<>();
        LinkedHashMap<String, Object> vcConfig = new LinkedHashMap<>();
        vcConfig.put("format", "ldp_vc");
        vcConfig.put("scope", "test-scope");
        vcConfig.put("credential_signing_alg_values_supported", List.of("Ed25519Signature2020"));
        Map<String, Object> proofTypes = Map.of("jwt", Map.of("proof_signing_alg_values_supported", List.of("RS256", "PS256")));
        vcConfig.put("proof_types_supported", proofTypes);
        List<Map<String, Object>> displayList = List.of(Map.of("name", "test-cred", "background_image", "https://background-image.png"));
        vcConfig.put("display", displayList);
        LinkedHashMap<String, Object> credDef = new LinkedHashMap<>();
        credDef.put("type", Arrays.asList("VerifiableCredential", "TestCredential"));
        vcConfig.put("credential_definition", credDef);
        credentialConfig.put("test-credential", vcConfig);
        latestMetadata.put("credential_configurations_supported", credentialConfig);
        latestMetadata.put("credential_issuer", "https://localhost:9090");
        latestMetadata.put("credential_endpoint", "https://localhost:9090/v1/certify/issuance/credential");
        issuerMetadata.put("latest", latestMetadata);

        ReflectionTestUtils.setField(issuanceService, "issuerMetadata", issuerMetadata);
        ReflectionTestUtils.setField(issuanceService, "vcSignAlgorithm", "Ed25519Signature2020");
        ReflectionTestUtils.setField(issuanceService, "cNonceExpireSeconds", 300);
        ReflectionTestUtils.setField(issuanceService, "issuerURI", "https://test.issuer.com");

        when(parsedAccessToken.getAccessTokenHash()).thenReturn(TEST_ACCESS_TOKEN_HASH);

        request = createValidCredentialRequest();
        claims = new HashMap<>();
        claims.put("scope", "test-scope");
        claims.put("client_id", "test-client");
        request.setClaims(claims);
        CredentialDefinition credentialDefinition = new CredentialDefinition();
        credentialDefinition.setContext(List.of("https://example.com"));
        credentialDefinition.setType(List.of("VerifiableCredential", "TestCredential"));
        request.setCredential_definition(credentialDefinition);
        transaction = new VCIssuanceTransaction();
        transaction.setCNonce(TEST_CNONCE);
        transaction.setCNonceExpireSeconds(300);
        transaction.setCNonceIssuedEpoch(LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC));
        vcResult = new VCResult<>();
        JsonLDObject jsonLDObject = new JsonLDObject();  // Create an actual JsonLDObject
        vcResult.setCredential(jsonLDObject);

        ReflectionTestUtils.setField(issuanceService, "issuerPublicKeyURI", ISSUER_PUBLIC_KEY_URI);
    }

    @Test
    public void getCredential_WithValidTransaction_Success() throws DataProviderExchangeException, JsonLDException, GeneralSecurityException, IOException {
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claims);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(any())).thenReturn(proofValidator);
        when(proofValidator.validate(any(), eq(TEST_CNONCE), any())).thenReturn(true);
        when(dataProviderPlugin.fetchData(any())).thenReturn(new JSONObject());
        when(vcFormatter.format(anyMap())).thenReturn("{\"name\":\"John Doe\",\"sdClaimPath\":\"hidden\"}");

        when(vcFormatter.getProofAlgorithm(anyString())).thenReturn("EdDSA");
        when(vcFormatter.getAppID(anyString())).thenReturn("appId");
        when(vcFormatter.getRefID(anyString())).thenReturn("refId");
        when(vcFormatter.getDidUrl(anyString())).thenReturn("did:example:issuer");
        W3cJsonLd w3cJsonLd = new W3cJsonLd(vcFormatter, signatureService);

        when(credentialFactory.getCredential("ldp_vc")).thenReturn(Optional.of(w3cJsonLd));
        ReflectionTestUtils.setField(w3cJsonLd, "proofGenerator", proofGenerator);

        Canonicalizer canonicalizer = mock(Canonicalizer.class);
        when(proofGenerator.getCanonicalizer()).thenReturn(canonicalizer);
        when(proofGenerator.getName()).thenReturn("RsaSignature2018");
        when(canonicalizer.canonicalize(any(LdProof.class), any(JsonLDObject.class)))
                .thenReturn("canonicalized".getBytes());

        LdProof ldProof = LdProof.builder()
                .type("RsaSignature2018")
                .created(new Date())
                .proofPurpose("assertionMethod")
                .verificationMethod(URI.create("https://example.com/key"))
                .build();

        when(proofGenerator.generateProof(any(LdProof.class), anyString(), anyMap())).thenReturn(ldProof);

        // Act
        CredentialResponse<?> response = issuanceService.getCredential(request);

        // Assert
        assertNotNull(response);
        verify(auditWrapper).logAudit(any(), any(), any(), any());
    }

    @Test
    public void getCredential_ValidRequest_NullJSONLD_Fail() throws DataProviderExchangeException {
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claims);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(any())).thenReturn(proofValidator);
        when(proofValidator.validate(any(), any(), any())).thenReturn(true);
        when(dataProviderPlugin.fetchData(any())).thenReturn(new JSONObject());
        when(credentialFactory.getCredential(anyString())).thenThrow(new CertifyException(UNSUPPORTED_VC_FORMAT));

        assertThrows(ErrorConstants.VC_ISSUANCE_FAILED, CertifyException.class, () -> issuanceService.getCredential(request));
    }

    @Test
    public void getCredential_ValidRequest_DataProviderException_Fail() throws DataProviderExchangeException {
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claims);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(any())).thenReturn(proofValidator);
        when(proofValidator.validate(any(), any(), any())).thenReturn(true);

        DataProviderExchangeException e = new DataProviderExchangeException("Failed to fetch data");
        when(dataProviderPlugin.fetchData(any())).thenThrow(e);
        assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
    }

    @Test
    public void getCredential_ExpiredNonce_ThrowsInvalidNonceException() {
        VCIssuanceTransaction newTransaction = new VCIssuanceTransaction();
        newTransaction.setCNonce("new-cnonce");
        newTransaction.setCNonceExpireSeconds(300);
        newTransaction.setCNonceIssuedEpoch(0L);

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claims);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(newTransaction);
        when(securityHelperService.generateSecureRandomString(20)).thenReturn("new-cnonce");
        when(vciCacheService.setVCITransaction(eq(TEST_ACCESS_TOKEN_HASH), any()))
                .thenReturn(transaction);

        assertThrows(InvalidNonceException.class, () -> issuanceService.getCredential(request));
    }

    @Test
    public void getCredential_NullTransaction_ThrowsInvalidCnonceException() throws VCIExchangeException {
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claims);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(null);
        when(vciCacheService.setVCITransaction(any(String.class), any(VCIssuanceTransaction.class))).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(any())).thenReturn(proofValidator);

        // Act
        assertThrows(InvalidNonceException.class, () -> issuanceService.getCredential(request));
    }

    @Test
    public void getCredential_ValidRequest_InvalidFormat_Fail() throws DataProviderExchangeException {
        request.setFormat("test-vc");
        assertThrows(ErrorConstants.INVALID_REQUEST, CertifyException.class, () -> issuanceService.getCredential(request));
    }

    @Test
    public void getCredential_ValidRequest_InvalidScope_Fail() throws DataProviderExchangeException {
        claims.put("scope", "test-new-scope");
        when(parsedAccessToken.isActive()).thenReturn(true);
        assertThrows(ErrorConstants.INVALID_SCOPE, CertifyException.class, () -> issuanceService.getCredential(request));
    }

    @Test
    public void getCredential_ValidRequest_InvalidProof_Fail() throws DataProviderExchangeException {
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claims);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(any())).thenReturn(proofValidator);
        when(proofValidator.validate(any(), any(), any())).thenReturn(false);

        assertThrows(ErrorConstants.INVALID_PROOF, CertifyException.class, () -> issuanceService.getCredential(request));
    }

    private CredentialRequest createValidCredentialRequest() {
        CredentialRequest request = new CredentialRequest();
        request.setFormat("ldp_vc");

        CredentialDefinition credDef = new CredentialDefinition();
        credDef.setContext(Arrays.asList("https://www.w3.org/2018/credentials/v1"));
        credDef.setType(Arrays.asList("VerifiableCredential", "TestCredential"));
        credDef.setCredentialSubject(new HashMap<>());
        request.setCredential_definition(credDef);

        CredentialProof proof = new CredentialProof();
        proof.setProof_type("test-proof");
        proof.setJwt("jwt");
        proof.setCwt("cwt");
        request.setProof(proof);

        return request;
    }

    @Test
    public void getCredentialIssuerMetadata_valid() {
        Map<String, Object> actual = issuanceService.getCredentialIssuerMetadata("latest");
        assertNotNull(actual);
    }

    @Test
    public void getCredentialIssuerMetadataVD11_valid() {
        Map<String, Object> actual = issuanceService.getCredentialIssuerMetadata("vd11");
        assertNotNull(actual);
        assertTrue(actual.containsKey("credential_issuer"));
        assertTrue(actual.containsKey("credential_endpoint"));
        assertEquals("https://localhost:9090/v1/certify/issuance/vd11/credential", actual.get("credential_endpoint"));
    }

    @Test
    public void getCredentialIssuerMetadataVD12_valid() {
        Map<String, Object> actual = issuanceService.getCredentialIssuerMetadata("vd12");
        assertNotNull(actual);
        assertTrue(actual.containsKey("credential_issuer"));
        assertTrue(actual.containsKey("credential_endpoint"));
        assertEquals("https://localhost:9090/v1/certify/issuance/vd12/credential", actual.get("credential_endpoint"));
    }

    @Test
    public void getCredentialIssuerMetadata_invalid() {
        assertThrows(InvalidRequestException.class, () -> issuanceService.getCredentialIssuerMetadata("latestData"));
        assertThrows(ErrorConstants.UNSUPPORTED_OPENID_VERSION, InvalidRequestException.class, () -> issuanceService.getCredentialIssuerMetadata(null));
    }

    @Test
    public void getVerifiableCredential_invalidRequest() {
        CredentialRequest cr = new CredentialRequest();
        cr.setFormat("fake-format");
        assertThrows(ErrorConstants.INVALID_REQUEST, InvalidRequestException.class,
                () -> issuanceService.getCredential(cr));
    }

    @Test
    public void getVerifiableCredential_invalidScope() {
        CredentialRequest cr = new CredentialRequest();
        cr.setFormat(VCFormats.LDP_VC);
        cr.setCredential_definition(new CredentialDefinition());
        when(parsedAccessToken.isActive()).thenReturn(false);
        assertThrows(NotAuthenticatedException.class, () -> issuanceService.getCredential(cr));
    }

    @Test
    public void getCredential_SDJWT_Success() throws Exception {
        request.setFormat("vc+sd-jwt");

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claims);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(any())).thenReturn(proofValidator);
        when(proofValidator.validate(any(), eq(TEST_CNONCE), any())).thenReturn(true);
        when(dataProviderPlugin.fetchData(any())).thenReturn(new JSONObject().put("key", "value"));

        // Required for SDJWT: mock format() to return a valid JSON string
        when(vcFormatter.format(anyMap())).thenReturn("{\"name\":\"John Doe\",\"sdClaimPath\":\"hidden\"}");

        // Mock other VCFormatter fields
        when(vcFormatter.getSelectiveDisclosureInfo(anyString())).thenReturn(List.of("$.sdClaimPath"));
        when(vcFormatter.getProofAlgorithm(anyString())).thenReturn("EdDSA");
        when(vcFormatter.getAppID(anyString())).thenReturn("appId");
        when(vcFormatter.getRefID(anyString())).thenReturn("refId");
        when(vcFormatter.getDidUrl(anyString())).thenReturn("did:example:issuer");

        // Mock signature service
        JWTSignatureResponseDto mockResponse = new JWTSignatureResponseDto();
        mockResponse.setJwtSignedData("signed.header.payload");
        when(signatureService.jwsSign(any())).thenReturn(mockResponse);

        // Use real SDJWT, injected with mocks
        SDJWT sdjwt = new SDJWT(vcFormatter, signatureService);

        // Now that credentialFactory is a mock, use proper stubbing
        when(credentialFactory.getCredential("vc+sd-jwt")).thenReturn(Optional.of(sdjwt));

        // ACT
        CredentialResponse<?> response = issuanceService.getCredential(request);

        // ASSERT
        assertNotNull(response);
        assertTrue(response.getCredential() instanceof String);
        String credential = (String) response.getCredential();
        assertTrue(credential.contains("~")); // SD-JWT disclosure separator
        verify(auditWrapper).logAudit(any(), any(), any(), any());
    }

    @Test
    public void getCredential_SDJWT_DataProviderException_Fail() throws DataProviderExchangeException {
        request.setFormat("vc+sd-jwt");
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claims);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(any())).thenReturn(proofValidator);
        when(proofValidator.validate(any(), any(), any())).thenReturn(true);

        DataProviderExchangeException ex = new DataProviderExchangeException("Data fetch failed");
        when(dataProviderPlugin.fetchData(any())).thenThrow(ex);

        assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
    }

    @Test
    public void getCredential_SDJWT_UnsupportedFormat_Fail() throws DataProviderExchangeException {
        request.setFormat("vc+sd-jwt");
        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claims);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(any())).thenReturn(proofValidator);
        when(proofValidator.validate(any(), any(), any())).thenReturn(true);
        when(dataProviderPlugin.fetchData(any())).thenReturn(new JSONObject());

        when(credentialFactory.getCredential("vc+sd-jwt")).thenReturn(Optional.empty());

        assertThrows(CertifyException.class, () -> issuanceService.getCredential(request));
    }

    @Test
    public void getCredential_SDJWT_InvalidDisclosures_Fail() throws Exception {
        request.setFormat("vc+sd-jwt");

        when(parsedAccessToken.isActive()).thenReturn(true);
        when(parsedAccessToken.getClaims()).thenReturn(claims);
        when(vciCacheService.getVCITransaction(TEST_ACCESS_TOKEN_HASH)).thenReturn(transaction);
        when(proofValidatorFactory.getProofValidator(any())).thenReturn(proofValidator);
        when(proofValidator.validate(any(), eq(TEST_CNONCE), any())).thenReturn(true);
        when(dataProviderPlugin.fetchData(any())).thenReturn(new JSONObject().put("key", "value"));

        // Return valid JSON, even though it's irrelevant (disclosures will be empty)
        when(vcFormatter.format(anyMap())).thenReturn("{\"none\":\"\"}");

        // No disclosures should trigger fallback JWT creation
        when(vcFormatter.getSelectiveDisclosureInfo(anyString())).thenReturn(List.of());

        JWTSignatureResponseDto mockResponse = new JWTSignatureResponseDto();
        mockResponse.setJwtSignedData("signedPayload");
        when(signatureService.jwsSign(any())).thenReturn(mockResponse);

        SDJWT sdjwt = new SDJWT(vcFormatter, signatureService);
        when(credentialFactory.getCredential("vc+sd-jwt")).thenReturn(Optional.of(sdjwt));

        CredentialResponse<?> response = issuanceService.getCredential(request);

        assertNotNull(response);
        String jwt = (String) response.getCredential();

        assertEquals("signedPayload~", jwt);
        verify(signatureService).jwsSign(any());
        verify(auditWrapper).logAudit(any(), any(), any(), any());
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