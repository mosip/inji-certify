package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.VCApiIssueOptions;
import io.mosip.certify.core.dto.VCApiIssueRequest;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.CredentialConfigException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class VCApiIssuanceServiceTest {

    @Mock
    private CredentialConfigurationService credentialConfigurationService;

    @Mock
    private VCApiCredentialIssuer vcApiCredentialIssuer;

    @InjectMocks
    private VCApiIssuanceService vcApiIssuanceService;

    @Test
    public void should_loadConfigAndIssue_when_headerConfigIdProvided() throws Exception {
        VCApiIssueRequest request = requestWithCredential();
        CredentialConfigurationDTO config = ldpConfig();
        when(credentialConfigurationService.getCredentialConfigurationById("farmer-credential")).thenReturn(config);

        JsonLDObject signedVc = JsonLDObject.fromJson("{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"]}");
        when(vcApiCredentialIssuer.issueValidatedCredential(eq(request.getCredential()), eq(config)))
                .thenReturn(new VCApiCredentialIssuer.VCApiIssueResult(signedVc));

        Map<String, Object> response = vcApiIssuanceService.issue(request, "farmer-credential");

        assertNotNull(response);
        assertNotNull(response.get("type"));
        verify(credentialConfigurationService).getCredentialConfigurationById("farmer-credential");
        verify(vcApiCredentialIssuer).issueValidatedCredential(any(), eq(config));
    }

    @Test
    public void should_returnCredentialMap_when_signedVcIssued() throws Exception {
        VCApiIssueRequest request = requestWithCredential();
        CredentialConfigurationDTO config = ldpConfig();
        when(credentialConfigurationService.getCredentialConfigurationById("farmer-credential")).thenReturn(config);

        JsonLDObject signedVc = JsonLDObject.fromJson(
                "{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"],\"credentialSubject\":{\"fullName\":\"Jane Doe\"}}");
        when(vcApiCredentialIssuer.issueValidatedCredential(eq(request.getCredential()), eq(config)))
                .thenReturn(new VCApiCredentialIssuer.VCApiIssueResult(signedVc));

        Map<String, Object> response = vcApiIssuanceService.issue(request, "farmer-credential");

        assertEquals("Jane Doe",
                ((Map<?, ?>) response.get("credentialSubject")).get("fullName"));
    }

    @Test
    public void should_propagateCertifyException_when_issuerThrows() throws Exception {
        VCApiIssueRequest request = requestWithCredential();
        CredentialConfigurationDTO config = ldpConfig();
        when(credentialConfigurationService.getCredentialConfigurationById("unknown-config")).thenReturn(config);
        when(vcApiCredentialIssuer.issueValidatedCredential(any(), eq(config)))
                .thenThrow(new CertifyException(ErrorConstants.CONFIG_NOT_FOUND_BY_ID, "Config not found"));

        CertifyException ex = assertThrows(CertifyException.class,
                () -> vcApiIssuanceService.issue(request, "unknown-config"));
        assertEquals(ErrorConstants.CONFIG_NOT_FOUND_BY_ID, ex.getErrorCode());
    }

    @Test
    public void should_wrapCredentialConfigException_when_configMissing() throws Exception {
        VCApiIssueRequest request = requestWithCredential();
        CredentialConfigException cause =
                new CredentialConfigException(ErrorConstants.CONFIG_NOT_FOUND_BY_ID, "Config not found");
        when(credentialConfigurationService.getCredentialConfigurationById("unknown-config"))
                .thenThrow(cause);

        CertifyException ex = assertThrows(CertifyException.class,
                () -> vcApiIssuanceService.issue(request, "unknown-config"));
        assertEquals(ErrorConstants.CONFIG_NOT_FOUND_BY_ID, ex.getErrorCode());
        assertSame(cause, ex.getCause());
        verify(vcApiCredentialIssuer, never()).issueValidatedCredential(any(), any());
    }

    @Test
    public void should_issueSuccessfully_when_optionsEmpty() throws Exception {
        VCApiIssueRequest request = requestWithCredential();
        request.setOptions(new VCApiIssueOptions());
        CredentialConfigurationDTO config = ldpConfig();
        when(credentialConfigurationService.getCredentialConfigurationById("farmer-credential")).thenReturn(config);

        JsonLDObject signedVc = JsonLDObject.fromJson("{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"]}");
        when(vcApiCredentialIssuer.issueValidatedCredential(eq(request.getCredential()), eq(config)))
                .thenReturn(new VCApiCredentialIssuer.VCApiIssueResult(signedVc));

        Map<String, Object> response = vcApiIssuanceService.issue(request, "farmer-credential");

        assertNotNull(response.get("type"));
        verify(vcApiCredentialIssuer).issueValidatedCredential(any(), eq(config));
    }

    @Test
    public void should_rejectRequest_when_optionsContainProofHints() throws Exception {
        VCApiIssueRequest request = requestWithCredential();
        VCApiIssueOptions options = new VCApiIssueOptions();
        options.setChallenge("nonce-123");
        request.setOptions(options);

        CertifyException ex = assertThrows(CertifyException.class,
                () -> vcApiIssuanceService.issue(request, "farmer-credential"));
        assertEquals(ErrorConstants.UNKNOWN_OPTION_PROVIDED, ex.getErrorCode());
        verify(credentialConfigurationService, never()).getCredentialConfigurationById(any());
        verify(vcApiCredentialIssuer, never()).issueValidatedCredential(any(), any());
    }

    private VCApiIssueRequest requestWithCredential() {
        VCApiIssueRequest request = new VCApiIssueRequest();
        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("@context", List.of(VCDM2Constants.URL));
        credential.put("type", List.of("VerifiableCredential", "FarmerCredential"));
        credential.put("issuer", "did:web:test.issuer");
        credential.put("credentialSubject", Map.of("fullName", "Jane Doe"));
        request.setCredential(credential);
        return request;
    }

    private CredentialConfigurationDTO ldpConfig() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialConfigKeyId("farmer-credential");
        config.setCredentialFormat(VCFormats.LDP_VC);
        return config;
    }
}
