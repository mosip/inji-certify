package io.mosip.certify.services;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.*;
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
    public void generatePreAuthorizedCode_InvalidConfigId() {
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

        Assert.assertTrue(exception.getMessage().contains("Missing mandatory claims"));
    }

    @Test
    public void generatePreAuthorizedCode_UnknownClaim() {
        request.getClaims().put("unknown", "value");

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> preAuthorizedCodeService.generatePreAuthorizedCode(request));

        Assert.assertTrue(exception.getMessage().contains("Unknown claims"));
    }

    @Test
    public void generatePreAuthorizedCode_ExpiryTooLow() {
        request.setExpiresIn(10);

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> preAuthorizedCodeService.generatePreAuthorizedCode(request));

        Assert.assertTrue(exception.getMessage().contains("expires_in must be between"));
    }

    @Test
    public void generatePreAuthorizedCode_ExpiryTooHigh() {
        request.setExpiresIn(100000);

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> preAuthorizedCodeService.generatePreAuthorizedCode(request));

        Assert.assertTrue(exception.getMessage().contains("expires_in must be between"));
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
}
