package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialLedgerService;
import io.mosip.certify.credential.CredentialFactory;
import io.mosip.certify.credential.W3CJsonLD;
import io.mosip.certify.utils.LedgerUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import org.mockito.InOrder;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.ArgumentCaptor;

@RunWith(MockitoJUnitRunner.class)
public class VCApiCredentialIssuerTest {

    private static final String DID_URL = "did:web:test.issuer";

    @InjectMocks
    private VCApiCredentialIssuer vcApiCredentialIssuer;

    @Mock
    private CredentialFactory credentialFactory;
    @Mock
    private StatusListCredentialService statusListCredentialService;
    @Mock
    private CredentialLedgerService credentialLedgerService;
    @Mock
    private LedgerUtils ledgerUtils;

    @Before
    public void setUp() {
        ReflectionTestUtils.setField(vcApiCredentialIssuer, "isLedgerEnabled", false);
        ReflectionTestUtils.setField(vcApiCredentialIssuer, "defaultExpiryDuration", "P730D");
    }

    @Test
    public void should_throwInvalidRequest_when_proofPresent() {
        Map<String, Object> credential = validCredential();
        credential.put("proof", Map.of("type", "DataIntegrityProof"));

        CertifyException ex = assertThrows(CertifyException.class,
                () -> vcApiCredentialIssuer.issueValidatedCredential(credential, ldpConfig()));
        assertEquals(ErrorConstants.INVALID_REQUEST, ex.getErrorCode());
    }

    @Test
    public void should_throwUnsupportedFormat_when_credentialFormatNotLdpVc() {
        CredentialConfigurationDTO config = ldpConfig();
        config.setCredentialFormat(VCFormats.DC_SD_JWT);

        CertifyException ex = assertThrows(CertifyException.class,
                () -> vcApiCredentialIssuer.issueValidatedCredential(validCredential(), config));
        assertEquals(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT, ex.getErrorCode());
    }

    @Test
    public void should_throwInvalidRequest_when_vcdm2ContextMissing() {
        Map<String, Object> credential = validCredential();
        credential.put("@context", List.of("https://www.w3.org/2018/credentials/v1"));

        CertifyException ex = assertThrows(CertifyException.class,
                () -> vcApiCredentialIssuer.issueValidatedCredential(credential, ldpConfig()));
        assertEquals(ErrorConstants.INVALID_REQUEST, ex.getErrorCode());
    }

    @Test
    public void should_throwInvalidRequest_when_contextDoesNotMatchConfig() {
        CredentialConfigurationDTO config = ldpConfig();
        config.setContextURLs(List.of(VCDM2Constants.URL, "https://example.org/missing-context"));

        CertifyException ex = assertThrows(CertifyException.class,
                () -> vcApiCredentialIssuer.issueValidatedCredential(validCredential(), config));
        assertEquals(ErrorConstants.INVALID_REQUEST, ex.getErrorCode());
    }

    @Test
    public void should_throwInvalidRequest_when_typeDoesNotMatchConfig() {
        CredentialConfigurationDTO config = ldpConfig();
        config.setCredentialTypes(List.of("VerifiableCredential", "OtherCredential"));

        CertifyException ex = assertThrows(CertifyException.class,
                () -> vcApiCredentialIssuer.issueValidatedCredential(validCredential(), config));
        assertEquals(ErrorConstants.INVALID_REQUEST, ex.getErrorCode());
    }

    @Test
    public void should_throwInvalidRequest_when_issuerDoesNotMatchConfig() {
        Map<String, Object> credential = validCredential();
        credential.put("issuer", "did:web:other.issuer");

        CertifyException ex = assertThrows(CertifyException.class,
                () -> vcApiCredentialIssuer.issueValidatedCredential(credential, ldpConfig()));
        assertEquals(ErrorConstants.INVALID_REQUEST, ex.getErrorCode());
    }

    @Test
    public void should_throwInvalidRequest_when_credentialStatusPurposesMissing() {
        CredentialConfigurationDTO config = ldpConfig();
        config.setCredentialStatusPurposes(null);

        CertifyException ex = assertThrows(CertifyException.class,
                () -> vcApiCredentialIssuer.issueValidatedCredential(validCredential(), config));
        assertEquals(ErrorConstants.INVALID_REQUEST, ex.getErrorCode());
        verify(statusListCredentialService, never()).addCredentialStatus(any(), anyString());
        verify(credentialLedgerService, never()).storeLedgerEntry(any(), any(), any(), any(), any(), any());
    }

    @Test
    public void should_addMandatoryCredentialStatus_when_issuanceSucceeds() throws Exception {
        CredentialConfigurationDTO config = ldpConfig();
        W3CJsonLD credentialBean = org.mockito.Mockito.mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(credentialBean));

        JsonLDObject signed = JsonLDObject.fromJson(
                "{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"],\"issuer\":\"" + DID_URL + "\"}");
        VCResult<JsonLDObject> result = new VCResult<>();
        result.setCredential(signed);
        when(credentialBean.addProof(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenAnswer(invocation -> result);

        VCApiCredentialIssuer.VCApiIssueResult issued =
                vcApiCredentialIssuer.issueValidatedCredential(validCredential(), config);

        assertNotNull(issued.verifiableCredential());
        verify(statusListCredentialService).addCredentialStatus(any(), eq("revocation"));
        verify(credentialLedgerService, never()).storeLedgerEntry(any(), any(), any(), any(), any(), any());
    }

    @Test
    public void should_storeLedgerAfterSigning_when_ledgerEnabled() throws Exception {
        ReflectionTestUtils.setField(vcApiCredentialIssuer, "isLedgerEnabled", true);
        CredentialConfigurationDTO config = ldpConfig();

        W3CJsonLD credentialBean = org.mockito.Mockito.mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(credentialBean));
        JsonLDObject signed = JsonLDObject.fromJson("{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"]}");
        VCResult<JsonLDObject> result = new VCResult<>();
        result.setCredential(signed);
        when(credentialBean.addProof(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenAnswer(invocation -> result);
        when(ledgerUtils.extractIndexedAttributes(any())).thenReturn(Map.of());
        when(ledgerUtils.extractCredentialStatusDetails(any())).thenReturn(null);

        vcApiCredentialIssuer.issueValidatedCredential(validCredential(), config);

        InOrder order = inOrder(statusListCredentialService, credentialBean, credentialLedgerService);
        order.verify(statusListCredentialService).addCredentialStatus(any(), eq("revocation"));
        order.verify(credentialBean).addProof(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString());
        order.verify(credentialLedgerService).storeLedgerEntry(eq("http://example.gov/credentials/1"), eq(DID_URL),
                anyString(), any(), any(), any());
    }

    @Test
    public void should_skipLedger_when_signingFails() throws Exception {
        ReflectionTestUtils.setField(vcApiCredentialIssuer, "isLedgerEnabled", true);
        CredentialConfigurationDTO config = ldpConfig();

        W3CJsonLD credentialBean = org.mockito.Mockito.mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(credentialBean));
        when(credentialBean.addProof(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenThrow(new CertifyException(ErrorConstants.INVALID_REQUEST, "signing failed"));

        CertifyException ex = assertThrows(CertifyException.class,
                () -> vcApiCredentialIssuer.issueValidatedCredential(validCredential(), config));
        assertEquals(ErrorConstants.INVALID_REQUEST, ex.getErrorCode());

        verify(statusListCredentialService).addCredentialStatus(any(), eq("revocation"));
        verify(credentialLedgerService, never()).storeLedgerEntry(any(), any(), any(), any(), any(), any());
    }

    @Test
    public void should_skipLedger_when_signedCredentialMissing() throws Exception {
        ReflectionTestUtils.setField(vcApiCredentialIssuer, "isLedgerEnabled", true);
        CredentialConfigurationDTO config = ldpConfig();

        W3CJsonLD credentialBean = org.mockito.Mockito.mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(credentialBean));
        VCResult<JsonLDObject> result = new VCResult<>();
        result.setCredential(null);
        when(credentialBean.addProof(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenAnswer(invocation -> result);

        CertifyException ex = assertThrows(CertifyException.class,
                () -> vcApiCredentialIssuer.issueValidatedCredential(validCredential(), config));
        assertEquals(ErrorConstants.VC_ISSUANCE_FAILED, ex.getErrorCode());

        verify(statusListCredentialService).addCredentialStatus(any(), eq("revocation"));
        verify(credentialLedgerService, never()).storeLedgerEntry(any(), any(), any(), any(), any(), any());
    }

    @Test
    public void should_throwInvalidRequest_when_subjectHasExtraFields() {
        CredentialConfigurationDTO config = ldpConfig();
        Map<String, Object> credential = validCredential();
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("id", "did:example:holder");
        subject.put("fullName", "Jane Doe");
        subject.put("email", "extra@example.com");
        credential.put("credentialSubject", subject);

        CertifyException ex = assertThrows(CertifyException.class,
                () -> vcApiCredentialIssuer.issueValidatedCredential(credential, config));
        assertEquals(ErrorConstants.INVALID_REQUEST, ex.getErrorCode());
    }

    @Test
    public void should_allowSubjectId_when_idMissingFromTemplate() throws Exception {
        CredentialConfigurationDTO config = ldpConfig();
        // template has fullName only; request may still include JSON-LD id
        config.setVcTemplate("""
                {
                  "credentialSubject": {
                    "fullName": "${fullName}"
                  }
                }
                """);
        Map<String, Object> credential = validCredential();
        credential.put("credentialSubject", Map.of("id", "did:example:holder", "fullName", "Jane Doe"));

        W3CJsonLD credentialBean = org.mockito.Mockito.mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(credentialBean));
        JsonLDObject signed = JsonLDObject.fromJson("{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"]}");
        VCResult<JsonLDObject> result = new VCResult<>();
        result.setCredential(signed);
        when(credentialBean.addProof(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenAnswer(invocation -> result);

        assertNotNull(vcApiCredentialIssuer.issueValidatedCredential(credential, config).verifiableCredential());
        verify(statusListCredentialService).addCredentialStatus(any(), eq("revocation"));
    }

    @Test
    public void should_throwInvalidRequestAndSkipSideEffects_when_validFromMalformed() {
        ReflectionTestUtils.setField(vcApiCredentialIssuer, "isLedgerEnabled", true);
        CredentialConfigurationDTO config = ldpConfig();
        Map<String, Object> credential = validCredential();
        credential.put("validFrom", "not-a-timestamp");

        CertifyException ex = assertThrows(CertifyException.class,
                () -> vcApiCredentialIssuer.issueValidatedCredential(credential, config));
        assertEquals(ErrorConstants.INVALID_REQUEST, ex.getErrorCode());
        verify(credentialLedgerService, never()).storeLedgerEntry(any(), any(), any(), any(), any(), any());
        verify(credentialFactory, never()).getCredential(anyString());
    }

    @Test
    public void should_defaultValidUntil_when_omittedFromRequest() throws Exception {
        CredentialConfigurationDTO config = ldpConfig();
        W3CJsonLD credentialBean = org.mockito.Mockito.mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(credentialBean));
        JsonLDObject signed = JsonLDObject.fromJson("{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"]}");
        VCResult<JsonLDObject> result = new VCResult<>();
        result.setCredential(signed);
        ArgumentCaptor<String> unsignedCaptor = ArgumentCaptor.forClass(String.class);
        when(credentialBean.addProof(unsignedCaptor.capture(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenAnswer(invocation -> result);

        assertNotNull(vcApiCredentialIssuer.issueValidatedCredential(validCredential(), config).verifiableCredential());

        org.json.JSONObject signedPayload = new org.json.JSONObject(unsignedCaptor.getValue());
        assertEquals("2026-01-01T00:00:00.000Z", signedPayload.getString(VCDM2Constants.VALID_FROM));
        assertEquals("2028-01-01T00:00:00.000Z", signedPayload.getString(VCDM2Constants.VALID_UNTIL));
    }

    @Test
    public void should_defaultValidFromAndValidUntil_when_bothOmittedFromRequest() throws Exception {
        CredentialConfigurationDTO config = ldpConfig();
        Map<String, Object> credential = validCredential();
        credential.remove("validFrom");
        credential.remove("validUntil");

        W3CJsonLD credentialBean = org.mockito.Mockito.mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(credentialBean));
        JsonLDObject signed = JsonLDObject.fromJson("{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"]}");
        VCResult<JsonLDObject> result = new VCResult<>();
        result.setCredential(signed);
        ArgumentCaptor<String> unsignedCaptor = ArgumentCaptor.forClass(String.class);
        when(credentialBean.addProof(unsignedCaptor.capture(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenAnswer(invocation -> result);

        Instant before = Instant.now().minusSeconds(2);
        assertNotNull(vcApiCredentialIssuer.issueValidatedCredential(credential, config).verifiableCredential());
        Instant after = Instant.now().plusSeconds(2);

        org.json.JSONObject signedPayload = new org.json.JSONObject(unsignedCaptor.getValue());
        Instant validFrom = Instant.parse(signedPayload.getString(VCDM2Constants.VALID_FROM));
        Instant validUntil = Instant.parse(signedPayload.getString(VCDM2Constants.VALID_UNTIL));
        assertTrue(validFrom.equals(before) || validFrom.isAfter(before));
        assertTrue(validFrom.equals(after) || validFrom.isBefore(after));
        assertEquals(Duration.parse("P730D"), Duration.between(validFrom, validUntil));
    }

    @Test
    public void should_parseBase64VcTemplate_when_templateIsEncoded() throws Exception {
        CredentialConfigurationDTO config = ldpConfig();
        String plainTemplate = config.getVcTemplate();
        config.setVcTemplate(org.apache.commons.codec.binary.Base64.encodeBase64String(
                plainTemplate.getBytes(StandardCharsets.UTF_8)));

        W3CJsonLD credentialBean = org.mockito.Mockito.mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(credentialBean));
        JsonLDObject signed = JsonLDObject.fromJson("{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"]}");
        VCResult<JsonLDObject> result = new VCResult<>();
        result.setCredential(signed);
        when(credentialBean.addProof(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenAnswer(invocation -> result);

        assertNotNull(vcApiCredentialIssuer.issueValidatedCredential(validCredential(), config).verifiableCredential());
        verify(statusListCredentialService).addCredentialStatus(any(), eq("revocation"));
    }

    @Test
    public void should_keepProvidedValidUntil_when_afterValidFrom() throws Exception {
        CredentialConfigurationDTO config = ldpConfig();
        Map<String, Object> credential = validCredential();
        credential.put("validUntil", "2026-06-01T00:00:00.000Z");
        W3CJsonLD credentialBean = org.mockito.Mockito.mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(credentialBean));
        JsonLDObject signed = JsonLDObject.fromJson("{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"]}");
        VCResult<JsonLDObject> result = new VCResult<>();
        result.setCredential(signed);
        ArgumentCaptor<String> unsignedCaptor = ArgumentCaptor.forClass(String.class);
        when(credentialBean.addProof(unsignedCaptor.capture(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenAnswer(invocation -> result);

        assertNotNull(vcApiCredentialIssuer.issueValidatedCredential(credential, config).verifiableCredential());

        org.json.JSONObject signedPayload = new org.json.JSONObject(unsignedCaptor.getValue());
        assertEquals("2026-06-01T00:00:00.000Z", signedPayload.getString(VCDM2Constants.VALID_UNTIL));
    }

    @Test
    public void should_throwInvalidExpiryRange_when_validUntilNotAfterValidFrom() {
        Map<String, Object> credential = validCredential();
        credential.put("validUntil", "2025-01-01T00:00:00.000Z");

        CertifyException ex = assertThrows(CertifyException.class,
                () -> vcApiCredentialIssuer.issueValidatedCredential(credential, ldpConfig()));
        assertEquals(ErrorConstants.INVALID_EXPIRY_RANGE, ex.getErrorCode());
        verify(credentialFactory, never()).getCredential(anyString());
    }

    @Test
    public void should_throwInvalidRequest_when_validUntilMalformed() {
        Map<String, Object> credential = validCredential();
        credential.put("validUntil", "not-a-timestamp");

        CertifyException ex = assertThrows(CertifyException.class,
                () -> vcApiCredentialIssuer.issueValidatedCredential(credential, ldpConfig()));
        assertEquals(ErrorConstants.INVALID_REQUEST, ex.getErrorCode());
        verify(credentialFactory, never()).getCredential(anyString());
    }

    @Test
    public void should_throwInvalidRequest_when_vcTemplateMissing() {
        CredentialConfigurationDTO config = ldpConfig();
        config.setVcTemplate(null);

        CertifyException ex = assertThrows(CertifyException.class,
                () -> vcApiCredentialIssuer.issueValidatedCredential(validCredential(), config));
        assertEquals(ErrorConstants.INVALID_REQUEST, ex.getErrorCode());
    }

    private Map<String, Object> validCredential() {
        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("@context", List.of(VCDM2Constants.URL, "https://example.org/examples/v2"));
        credential.put("id", "http://example.gov/credentials/1");
        credential.put("type", List.of("VerifiableCredential", "FarmerCredential"));
        credential.put("issuer", DID_URL);
        credential.put("validFrom", "2026-01-01T00:00:00.000Z");
        credential.put("credentialSubject", Map.of("id", "did:example:holder", "fullName", "Jane Doe"));
        return credential;
    }

    private CredentialConfigurationDTO ldpConfig() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialConfigKeyId("farmer-credential");
        config.setCredentialFormat(VCFormats.LDP_VC);
        config.setContextURLs(List.of(VCDM2Constants.URL, "https://example.org/examples/v2"));
        config.setCredentialTypes(List.of("VerifiableCredential", "FarmerCredential"));
        config.setDidUrl(DID_URL);
        config.setKeyManagerAppId("CERTIFY_VC_SIGN_ED25519");
        config.setKeyManagerRefId("ED25519_SIGN");
        config.setSignatureAlgo("Ed25519");
        config.setSignatureCryptoSuite("Ed25519Signature2020");
        config.setCredentialStatusPurposes(List.of("revocation"));
        config.setVcTemplate("""
                {
                  "@context": ["https://www.w3.org/ns/credentials/v2", "https://example.org/examples/v2"],
                  "type": ["VerifiableCredential", "FarmerCredential"],
                  "issuer": "${_issuer}",
                  "credentialSubject": {
                    "id": "${_holderId}",
                    "fullName": "${fullName}"
                  }
                }
                """);
        return config;
    }
}
