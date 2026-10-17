package io.mosip.certify.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.AccessTokenJwtUtil;
import jakarta.validation.Validator;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.*;

import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class PreAuthorizedCodeServiceTest {

    @Mock
    private VCICacheService vciCacheService;

    @Mock
    private AccessTokenJwtUtil accessTokenJwtUtil;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private CredentialConfigurationService credentialConfigurationService;

    @Mock
    private CredentialConfigRepository credentialConfigRepository;

    @Mock
    private Validator validator;

    private PreAuthorizedRequest request;
    private Map<String, Object> issuerMetadata;
    private Map<String, Object> supportedConfigs;
    private Map<String, Object> config;
    private CredentialIssuerMetadataDTO metadataDTO;
    private final String CONFIG_ID = "test-config";

    private PreAuthorizedCodeService preAuthorizedCodeService;
    @Before
    public void setup() throws Exception {
        preAuthorizedCodeService = new PreAuthorizedCodeService(
                vciCacheService,
                accessTokenJwtUtil,
                objectMapper,
                credentialConfigurationService,
                credentialConfigRepository,
                validator
        );
        ReflectionTestUtils.setField(preAuthorizedCodeService, "issuerIdentifier", "https://issuer.com");
        ReflectionTestUtils.setField(preAuthorizedCodeService, "defaultExpirySeconds", 600);
        ReflectionTestUtils.setField(preAuthorizedCodeService, "minExpirySeconds", 60);
        ReflectionTestUtils.setField(preAuthorizedCodeService, "maxExpirySeconds", 86400);
        ReflectionTestUtils.setField(preAuthorizedCodeService, "credentialOfferUrl", "https://credentialOffer.com/");
        ReflectionTestUtils.setField(preAuthorizedCodeService, "accessTokenExpirySeconds", 600);
        ReflectionTestUtils.setField(preAuthorizedCodeService, "oauthIssuer", "https://oauth.issuer.com");
        ReflectionTestUtils.setField(preAuthorizedCodeService, "oauthAudience", "https://oauth.audience.com");

        request = new PreAuthorizedRequest();
        request.setCredentialConfigurationId(CONFIG_ID);
        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "John Doe");
        request.setClaims(claims);

        issuerMetadata = new HashMap<>();
        supportedConfigs = new HashMap<>();
        config = new HashMap<>();
        Map<String, Object> requiredClaims = new HashMap<>();
        Map<String, Object> nameClaim = new HashMap<>();
        nameClaim.put(Constants.MANDATORY, true);
        requiredClaims.put("name", nameClaim);
        config.put(Constants.CLAIMS, requiredClaims);
        supportedConfigs.put(CONFIG_ID, config);
        issuerMetadata.put(Constants.CREDENTIAL_CONFIGURATIONS_SUPPORTED, supportedConfigs);

        // Mock ObjectMapper for JSON serialization
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"name\":\"John Doe\"}");
        // Setup mock for credentialConfigurationService
        Map<String, CredentialConfigurationSupportedDTO> supportedDTOMap = new LinkedHashMap<>();
        CredentialConfigurationSupportedDTO configDTO = new CredentialConfigurationSupportedDTO();
        CredentialMetadataDTO metadata = new CredentialMetadataDTO();
        List<CredentialMetadataDTO.Claims> claimsList = new ArrayList<>();

        CredentialMetadataDTO.Claims givenName = new CredentialMetadataDTO.Claims();
        givenName.setPath(List.of("credentialSubject", "name"));

        ClaimsDisplayFieldsConfigDTO.Display givenNameDisplay =
                new ClaimsDisplayFieldsConfigDTO.Display();
        givenNameDisplay.setName("Given Name");
        givenNameDisplay.setLocale("en-US");

        givenName.setDisplay(List.of(givenNameDisplay));
        givenName.setMandatory(true);

        claimsList.add(givenName);
        metadata.setClaims(claimsList);
        configDTO.setCredentialMetadataDTO(metadata);
        supportedDTOMap.put(CONFIG_ID, configDTO);



        metadataDTO = mock(CredentialIssuerMetadataDTO.class);
        when(metadataDTO.getCredentialConfigurationSupportedDTO()).thenReturn(supportedDTOMap);

        // KEY FIX: Mock the credentialConfigurationService to return metadataDTO
        when(credentialConfigurationService.fetchCredentialIssuerMetadata()).thenReturn(metadataDTO);

        // Mock credentialConfigRepository
        CredentialConfig credentialConfig = new CredentialConfig();
        credentialConfig.setStatus(Constants.ACTIVE);
        credentialConfig.setScope("test_scope");
        when(credentialConfigRepository.findByCredentialConfigKeyId(CONFIG_ID)).thenReturn(Optional.of(credentialConfig));
        when(validator.validate(any())).thenReturn(Collections.emptySet());
    }

    @Test
    public void generatePreAuthorizedCode_Success() {
        String result = preAuthorizedCodeService.generatePreAuthorizedCode(request);

        Assert.assertNotNull(result);
        Assert.assertTrue(result.startsWith("openid-credential-offer://?credential_offer_uri="));
        verify(vciCacheService).setPreAuthCodeData(anyString(), any(PreAuthCodeData.class));
        verify(vciCacheService).setCredentialOffer(anyString(), any(CredentialOfferResponse.class));
    }

    @Test
    public void generatePreAuthorizedCode_WithTxCode_Success() {
        request.setTxCode("1234");
        String result = preAuthorizedCodeService.generatePreAuthorizedCode(request);

        Assert.assertNotNull(result);
        verify(vciCacheService).setPreAuthCodeData(anyString(), any(PreAuthCodeData.class));
        verify(vciCacheService).setCredentialOffer(anyString(), any(CredentialOfferResponse.class));
    }

    @Test
    public void generatePreAuthorizedCode_Failure_If_InvalidConfigId() {
        request.setCredentialConfigurationId("invalid-id");

        // Update metadata mock to not include invalid-id
        Map<String, CredentialConfigurationSupportedDTO> emptyMap = new LinkedHashMap<>();
        when(metadataDTO.getCredentialConfigurationSupportedDTO()).thenReturn(emptyMap);

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                        () -> preAuthorizedCodeService.generatePreAuthorizedCode(request));

        Assert.assertEquals(ErrorConstants.INVALID_CREDENTIAL_CONFIGURATION_ID, exception.getMessage());
    }

    @Test
    public void generatePreAuthorizedCode_MissingMandatoryClaim() {
        request.getClaims().remove("name");

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> preAuthorizedCodeService.generatePreAuthorizedCode(request));

        Assert.assertEquals(ErrorConstants.MISSING_MANDATORY_CLAIM, exception.getErrorCode());
    }

    @Test
    public void generatePreAuthorizedCode_UnknownClaim() {
        request.getClaims().put("unknown", "value");

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> preAuthorizedCodeService.generatePreAuthorizedCode(request));

        Assert.assertEquals(ErrorConstants.UNKNOWN_CLAIMS, exception.getErrorCode());
    }

    @Test
    public void generatePreAuthorizedCode_ExpiryTooLow() {
        request.setExpiresIn(10);

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> preAuthorizedCodeService.generatePreAuthorizedCode(request));

        Assert.assertEquals(ErrorConstants.INVALID_EXPIRY_RANGE, exception.getErrorCode());
    }

    @Test
    public void generatePreAuthorizedCode_ExpiryTooHigh() {
        request.setExpiresIn(100000);

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> preAuthorizedCodeService.generatePreAuthorizedCode(request));

        Assert.assertEquals(ErrorConstants.INVALID_EXPIRY_RANGE, exception.getErrorCode());
    }

    @Test
    public void generatePreAuthorizedCode_RetryOnCollision_Success() {
        // First attempt returns existing data (collision), second returns null
        // (success)
        when(vciCacheService.getPreAuthCodeData(anyString()))
                .thenReturn(new PreAuthCodeData())
                .thenReturn(null);

        String result = preAuthorizedCodeService.generatePreAuthorizedCode(request);

        Assert.assertNotNull(result);
        // Should have called getPreAuthCodeData 2 times
        verify(vciCacheService, times(2)).getPreAuthCodeData(anyString());
    }

    @Test
    public void generatePreAuthorizedCode_MaxRetriesExceeded_Fail() {
        // Always returns existing data (collision)
        when(vciCacheService.getPreAuthCodeData(anyString())).thenReturn(new PreAuthCodeData());

        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> preAuthorizedCodeService.generatePreAuthorizedCode(request));

        Assert.assertTrue(exception.getMessage().contains("Failed to generate unique pre-authorized code"));
        // Should have tried MAX_ATTEMPTS (3)
        verify(vciCacheService, times(3)).getPreAuthCodeData(anyString());
    }

    // Tests for getCredentialOffer method

    @Test
    public void getCredentialOffer_Success() {
        String validUuid = "550e8400-e29b-41d4-a716-446655440000";
        CredentialOfferResponse expectedOffer = CredentialOfferResponse.builder()
                .credentialIssuer("https://issuer.com")
                .build();

        when(vciCacheService.getCredentialOffer(validUuid)).thenReturn(expectedOffer);

        CredentialOfferResponse result = preAuthorizedCodeService.getCredentialOffer(validUuid);

        Assert.assertNotNull(result);
        Assert.assertEquals(expectedOffer, result);
        verify(vciCacheService).getCredentialOffer(validUuid);
    }

    @Test
    public void getCredentialOffer_InvalidUuidFormat_ThrowsInvalidRequestException() {
        String invalidUuid = "not-a-valid-uuid";

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> preAuthorizedCodeService.getCredentialOffer(invalidUuid));

        Assert.assertEquals(ErrorConstants.INVALID_OFFER_ID_FORMAT, exception.getErrorCode());
        verify(vciCacheService, never()).getCredentialOffer(anyString());
    }

    @Test
    public void getCredentialOffer_NullOfferId_ThrowsInvalidRequestException() {
        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> preAuthorizedCodeService.getCredentialOffer(null));

        Assert.assertEquals(ErrorConstants.INVALID_OFFER_ID_FORMAT, exception.getErrorCode());
        verify(vciCacheService, never()).getCredentialOffer(anyString());
    }

    @Test
    public void getCredentialOffer_EmptyOfferId_ThrowsInvalidRequestException() {
        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> preAuthorizedCodeService.getCredentialOffer(""));

        Assert.assertEquals(ErrorConstants.INVALID_OFFER_ID_FORMAT, exception.getErrorCode());
        verify(vciCacheService, never()).getCredentialOffer(anyString());
    }

    @Test
    public void getCredentialOffer_WhitespaceOfferId_ThrowsInvalidRequestException() {
        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> preAuthorizedCodeService.getCredentialOffer("   "));

        Assert.assertEquals(ErrorConstants.INVALID_OFFER_ID_FORMAT, exception.getErrorCode());
        verify(vciCacheService, never()).getCredentialOffer(anyString());
    }

    @Test
    public void getCredentialOffer_NotFound_ThrowsCertifyException() {
        String validUuid = "550e8400-e29b-41d4-a716-446655440000";

        when(vciCacheService.getCredentialOffer(validUuid)).thenReturn(null);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> preAuthorizedCodeService.getCredentialOffer(validUuid));

        Assert.assertEquals(ErrorConstants.CREDENTIAL_OFFER_NOT_FOUND, exception.getErrorCode());
        verify(vciCacheService).getCredentialOffer(validUuid);
    }

    @Test
    public void exchangePreAuthorizedCode_Success() throws Exception {
        String preAuthCode = "test-pre-auth-code";
        OAuthTokenRequest tokenRequest = new OAuthTokenRequest();
        tokenRequest.setGrant_type(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPre_authorized_code(preAuthCode);

        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "John Doe");

        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .claims(claims)
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000) // expires in 10 minutes
                .build();

        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(codeData);
        when(vciCacheService.claimPreAuthCodeIfUnexpired(eq(preAuthCode), anyLong()))
                .thenReturn(VCICacheService.PreAuthCodeClaimResult.CLAIMED);
        when(vciCacheService.setPreAuthTransaction(anyString(), any(PreAuthTransaction.class))).thenReturn(null);
        when(accessTokenJwtUtil.generateSignedJwt(anyString(), anyString(), anyString(), anyString(), anyString(), anyInt()))
                .thenReturn("test.jwt.token");

        OAuthTokenResponse response = preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest);

        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getAccessToken());
        Assert.assertEquals("test.jwt.token", response.getAccessToken());
        Assert.assertEquals("Bearer", response.getTokenType());
        Assert.assertEquals(Integer.valueOf(600), response.getExpiresIn());

        verify(vciCacheService).getPreAuthCodeData(preAuthCode);
        verify(vciCacheService).claimPreAuthCodeIfUnexpired(eq(preAuthCode), anyLong());
        verify(vciCacheService).setPreAuthTransaction(anyString(), any(PreAuthTransaction.class));
    }

    @Test
    public void exchangePreAuthorizedCode_WithTxCode_Success() throws Exception {
        String preAuthCode = "test-pre-auth-code";
        String txCode = "1234";
        OAuthTokenRequest tokenRequest = new OAuthTokenRequest();
        tokenRequest.setGrant_type(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPre_authorized_code(preAuthCode);
        tokenRequest.setTx_code(txCode);

        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "John Doe");

        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .claims(claims)
                .txnCode(txCode)
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000)
                .build();

        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(codeData);
        when(vciCacheService.claimPreAuthCodeIfUnexpired(eq(preAuthCode), anyLong()))
                .thenReturn(VCICacheService.PreAuthCodeClaimResult.CLAIMED);
        when(vciCacheService.setPreAuthTransaction(anyString(), any(PreAuthTransaction.class))).thenReturn(null);
        when(accessTokenJwtUtil.generateSignedJwt(anyString(), anyString(), anyString(), anyString(), anyString(), anyInt()))
                .thenReturn("test.jwt.token");

        OAuthTokenResponse response = preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest);

        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getAccessToken());
        verify(vciCacheService).claimPreAuthCodeIfUnexpired(eq(preAuthCode), anyLong());
    }

    @Test
    public void exchangePreAuthorizedCode_UnsupportedGrantType_ThrowsCertifyException() {
        OAuthTokenRequest tokenRequest = new OAuthTokenRequest();
        tokenRequest.setGrant_type("invalid_grant_type");
        tokenRequest.setPre_authorized_code("test-code");

        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000)
                .build();

        when(vciCacheService.getPreAuthCodeData("test-code")).thenReturn(codeData);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest));

        Assert.assertEquals(ErrorConstants.UNSUPPORTED_GRANT_TYPE, exception.getErrorCode());
    }

    @Test
    public void exchangePreAuthorizedCode_InvalidPreAuthCode_ThrowsCertifyException() {
        OAuthTokenRequest tokenRequest = new OAuthTokenRequest();
        tokenRequest.setGrant_type(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPre_authorized_code("invalid-code");

        when(vciCacheService.getPreAuthCodeData("invalid-code")).thenReturn(null);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest));

        Assert.assertEquals(ErrorConstants.INVALID_GRANT, exception.getErrorCode());
    }

    @Test
    public void exchangePreAuthorizedCode_ExpiredCode_ThrowsCertifyException() {
        String preAuthCode = "expired-code";
        OAuthTokenRequest tokenRequest = new OAuthTokenRequest();
        tokenRequest.setGrant_type(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPre_authorized_code(preAuthCode);

        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .createdAt(System.currentTimeMillis() - 700000)
                .expiresAt(System.currentTimeMillis() - 100000) // expired
                .build();

        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(codeData);
        when(vciCacheService.claimPreAuthCodeIfUnexpired(eq(preAuthCode), anyLong()))
                .thenReturn(VCICacheService.PreAuthCodeClaimResult.EXPIRED);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest));

        Assert.assertEquals("pre_auth_code_expired", exception.getErrorCode());
        // Expiry and claim are validated atomically in cache layer
        verify(vciCacheService).claimPreAuthCodeIfUnexpired(eq(preAuthCode), anyLong());
    }

    @Test
    public void exchangePreAuthorizedCode_AlreadyUsedCode_ThrowsCertifyException() {
        String preAuthCode = "used-code";
        OAuthTokenRequest tokenRequest = new OAuthTokenRequest();
        tokenRequest.setGrant_type(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPre_authorized_code(preAuthCode);

        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000)
                .build();

        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(codeData);
        when(vciCacheService.claimPreAuthCodeIfUnexpired(eq(preAuthCode), anyLong()))
                .thenReturn(VCICacheService.PreAuthCodeClaimResult.INVALID_OR_USED);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest));

        Assert.assertEquals(ErrorConstants.INVALID_GRANT, exception.getErrorCode());
    }

    @Test
    public void exchangePreAuthorizedCode_TxCodeRequired_ThrowsCertifyException() {
        String preAuthCode = "test-code";
        OAuthTokenRequest tokenRequest = new OAuthTokenRequest();
        tokenRequest.setGrant_type(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPre_authorized_code(preAuthCode);

        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .txnCode("1234") // txCode is required
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000)
                .build();

        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(codeData);
        when(vciCacheService.claimPreAuthCodeIfUnexpired(eq(preAuthCode), anyLong()))
                .thenReturn(VCICacheService.PreAuthCodeClaimResult.CLAIMED);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest));

        Assert.assertEquals("tx_code_required", exception.getErrorCode());
    }

    @Test
    public void exchangePreAuthorizedCode_TxCodeMismatch_ThrowsCertifyException() {
        String preAuthCode = "test-code";
        OAuthTokenRequest tokenRequest = new OAuthTokenRequest();
        tokenRequest.setGrant_type(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPre_authorized_code(preAuthCode);
        tokenRequest.setTx_code("wrong-code");

        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .txnCode("1234") // expected txCode
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000)
                .build();

        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(codeData);
        when(vciCacheService.claimPreAuthCodeIfUnexpired(eq(preAuthCode), anyLong()))
                .thenReturn(VCICacheService.PreAuthCodeClaimResult.CLAIMED);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest));

        Assert.assertEquals("tx_code_mismatch", exception.getErrorCode());
    }
}
