package io.mosip.certify.services;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class PreAuthorizedCodeServiceTest {

    @Mock
    private VCICacheService vciCacheService;

    @InjectMocks
    private PreAuthorizedCodeService preAuthorizedCodeService;

    private PreAuthorizedRequest request;
    private Map<String, Object> issuerMetadata;
    private Map<String, Object> supportedConfigs;
    private Map<String, Object> config;
    private final String CONFIG_ID = "test-config";

    @Before
    public void setup() {
        ReflectionTestUtils.setField(preAuthorizedCodeService, "issuerIdentifier", "https://issuer.com");
        ReflectionTestUtils.setField(preAuthorizedCodeService, "defaultExpirySeconds", 600);
        ReflectionTestUtils.setField(preAuthorizedCodeService, "minExpirySeconds", 60);
        ReflectionTestUtils.setField(preAuthorizedCodeService, "maxExpirySeconds", 86400);
        ReflectionTestUtils.setField(preAuthorizedCodeService, "domainUrl", "https://domain.com/");

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

        when(vciCacheService.getIssuerMetadata()).thenReturn(issuerMetadata);
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

        Assert.assertEquals("offer_not_found", exception.getErrorCode());
        verify(vciCacheService).getCredentialOffer(validUuid);
    }

    @Test
    public void exchangePreAuthorizedCode_Success() {
        ReflectionTestUtils.setField(preAuthorizedCodeService, "accessTokenExpirySeconds", 600);
        ReflectionTestUtils.setField(preAuthorizedCodeService, "cNonceExpirySeconds", 300);
        ReflectionTestUtils.setField(preAuthorizedCodeService, "singleUsePreAuthCode", true);

        String preAuthCode = "test-pre-auth-code";
        TokenRequest tokenRequest = new TokenRequest();
        tokenRequest.setGrantType(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPreAuthorizedCode(preAuthCode);

        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "John Doe");

        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .claims(claims)
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000) // expires in 10 minutes
                .build();

        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(codeData);
        when(vciCacheService.isCodeBlacklisted(preAuthCode)).thenReturn(false);
        when(vciCacheService.setTransaction(anyString(), any(Transaction.class))).thenReturn(null);

        TokenResponse response = preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest);

        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getAccessToken());
        Assert.assertTrue(response.getAccessToken().startsWith("at_"));
        Assert.assertEquals("Bearer", response.getTokenType());
        Assert.assertEquals(Integer.valueOf(600), response.getExpiresIn());
        Assert.assertNotNull(response.getCNonce());
        Assert.assertEquals(Integer.valueOf(300), response.getCNonceExpiresIn());

        verify(vciCacheService).getPreAuthCodeData(preAuthCode);
        verify(vciCacheService).isCodeBlacklisted(preAuthCode);
        verify(vciCacheService).blacklistPreAuthCode(preAuthCode);
        verify(vciCacheService).setTransaction(anyString(), any(Transaction.class));
    }

    @Test
    public void exchangePreAuthorizedCode_WithTxCode_Success() {
        ReflectionTestUtils.setField(preAuthorizedCodeService, "accessTokenExpirySeconds", 600);
        ReflectionTestUtils.setField(preAuthorizedCodeService, "cNonceExpirySeconds", 300);
        ReflectionTestUtils.setField(preAuthorizedCodeService, "singleUsePreAuthCode", true);

        String preAuthCode = "test-pre-auth-code";
        String txCode = "1234";
        TokenRequest tokenRequest = new TokenRequest();
        tokenRequest.setGrantType(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPreAuthorizedCode(preAuthCode);
        tokenRequest.setTxCode(txCode);

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
        when(vciCacheService.isCodeBlacklisted(preAuthCode)).thenReturn(false);
        when(vciCacheService.setTransaction(anyString(), any(Transaction.class))).thenReturn(null);

        TokenResponse response = preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest);

        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getAccessToken());
        verify(vciCacheService).blacklistPreAuthCode(preAuthCode);
    }

    @Test
    public void exchangePreAuthorizedCode_UnsupportedGrantType_ThrowsCertifyException() {
        TokenRequest tokenRequest = new TokenRequest();
        tokenRequest.setGrantType("invalid_grant_type");
        tokenRequest.setPreAuthorizedCode("test-code");

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
        TokenRequest tokenRequest = new TokenRequest();
        tokenRequest.setGrantType(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPreAuthorizedCode("invalid-code");

        when(vciCacheService.getPreAuthCodeData("invalid-code")).thenReturn(null);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest));

        Assert.assertEquals(ErrorConstants.INVALID_GRANT, exception.getErrorCode());
    }

    @Test
    public void exchangePreAuthorizedCode_ExpiredCode_ThrowsCertifyException() {
        ReflectionTestUtils.setField(preAuthorizedCodeService, "singleUsePreAuthCode", true);

        String preAuthCode = "expired-code";
        TokenRequest tokenRequest = new TokenRequest();
        tokenRequest.setGrantType(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPreAuthorizedCode(preAuthCode);

        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .createdAt(System.currentTimeMillis() - 700000)
                .expiresAt(System.currentTimeMillis() - 100000) // expired
                .build();

        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(codeData);
        when(vciCacheService.isCodeBlacklisted(preAuthCode)).thenReturn(false);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest));

        Assert.assertEquals("pre_auth_code_expired", exception.getErrorCode());
    }

    @Test
    public void exchangePreAuthorizedCode_AlreadyUsedCode_ThrowsCertifyException() {
        ReflectionTestUtils.setField(preAuthorizedCodeService, "singleUsePreAuthCode", true);

        String preAuthCode = "used-code";
        TokenRequest tokenRequest = new TokenRequest();
        tokenRequest.setGrantType(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPreAuthorizedCode(preAuthCode);

        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000)
                .build();

        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(codeData);
        when(vciCacheService.isCodeBlacklisted(preAuthCode)).thenReturn(true);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest));

        Assert.assertEquals("pre_auth_code_already_used", exception.getErrorCode());
    }

    @Test
    public void exchangePreAuthorizedCode_TxCodeRequired_ThrowsCertifyException() {
        ReflectionTestUtils.setField(preAuthorizedCodeService, "singleUsePreAuthCode", true);

        String preAuthCode = "test-code";
        TokenRequest tokenRequest = new TokenRequest();
        tokenRequest.setGrantType(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPreAuthorizedCode(preAuthCode);
        // txCode not provided

        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .txnCode("1234") // txCode is required
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000)
                .build();

        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(codeData);
        when(vciCacheService.isCodeBlacklisted(preAuthCode)).thenReturn(false);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest));

        Assert.assertEquals("tx_code_required", exception.getErrorCode());
    }

    @Test
    public void exchangePreAuthorizedCode_TxCodeMismatch_ThrowsCertifyException() {
        ReflectionTestUtils.setField(preAuthorizedCodeService, "singleUsePreAuthCode", true);

        String preAuthCode = "test-code";
        TokenRequest tokenRequest = new TokenRequest();
        tokenRequest.setGrantType(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPreAuthorizedCode(preAuthCode);
        tokenRequest.setTxCode("wrong-code");

        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .txnCode("1234") // expected txCode
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000)
                .build();

        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(codeData);
        when(vciCacheService.isCodeBlacklisted(preAuthCode)).thenReturn(false);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest));

        Assert.assertEquals("tx_code_mismatch", exception.getErrorCode());
    }

    @Test
    public void exchangePreAuthorizedCode_SingleUseDisabled_DoesNotBlacklist() {
        ReflectionTestUtils.setField(preAuthorizedCodeService, "accessTokenExpirySeconds", 600);
        ReflectionTestUtils.setField(preAuthorizedCodeService, "cNonceExpirySeconds", 300);
        ReflectionTestUtils.setField(preAuthorizedCodeService, "singleUsePreAuthCode", false);

        String preAuthCode = "test-pre-auth-code";
        TokenRequest tokenRequest = new TokenRequest();
        tokenRequest.setGrantType(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        tokenRequest.setPreAuthorizedCode(preAuthCode);

        PreAuthCodeData codeData = PreAuthCodeData.builder()
                .credentialConfigurationId(CONFIG_ID)
                .claims(new HashMap<>())
                .createdAt(System.currentTimeMillis())
                .expiresAt(System.currentTimeMillis() + 600000)
                .build();

        when(vciCacheService.getPreAuthCodeData(preAuthCode)).thenReturn(codeData);
        when(vciCacheService.setTransaction(anyString(), any(Transaction.class))).thenReturn(null);

        TokenResponse response = preAuthorizedCodeService.exchangePreAuthorizedCode(tokenRequest);

        Assert.assertNotNull(response);
        verify(vciCacheService, never()).isCodeBlacklisted(anyString());
        verify(vciCacheService, never()).blacklistPreAuthCode(anyString());
    }
}

