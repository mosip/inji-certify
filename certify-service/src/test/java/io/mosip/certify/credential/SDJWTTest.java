package io.mosip.certify.credential;

import io.mosip.kernel.signature.service.CoseSignatureService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDtoV2;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.service.SignatureService;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class SDJWTTest {

    @Mock
    private VCFormatter mockFormatter;

    @Mock
    private SignatureService mockSignatureService;

    private ObjectMapper objectMapper = new ObjectMapper();

    private SDJWT sdjwt;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);
        sdjwt = new SDJWT(mockFormatter, mockSignatureService, mock(CoseSignatureService.class), objectMapper);
    }

    @Test
    public void testCanHandle_ShouldReturnTrueForCorrectFormat() {
        assertTrue(sdjwt.canHandle(VCFormats.DC_SD_JWT));
    }

    @Test
    public void testCanHandle_ShouldReturnFalseForIncorrectFormat() {
        assertFalse(sdjwt.canHandle(VCFormats.LDP_VC));
    }

    @Test
    public void testCreateCredential_WithValidInput_ReturnsSdJwt() throws JsonProcessingException {
        String mockTemplateName = "mockTemplate";
        Map<String, Object> templateParams = new HashMap<>();

        String templateJson = "{\"name\": \"John\", \"age\": 30}";
        when(mockFormatter.format(any(Map.class))).thenReturn(templateJson);
        when(mockFormatter.getSelectiveDisclosureInfo(mockTemplateName))
                .thenReturn(Arrays.asList("$.name"));

        String result = sdjwt.createCredential(templateParams, mockTemplateName);

        assertNotNull(result);
        assertTrue(result.contains("~"));
    }

    @Test
    public void should_throwCertifyException_when_sdClaimPathIsMissing() throws JsonProcessingException {
        String mockTemplateName = "mockTemplate";
        Map<String, Object> templateParams = new HashMap<>();

        String templateJson = "{\"name\": \"John\", \"age\": 30}";
        when(mockFormatter.format(any(Map.class))).thenReturn(templateJson);
        when(mockFormatter.getSelectiveDisclosureInfo(mockTemplateName))
                .thenReturn(Arrays.asList("$.invalid_claim"));
        when(mockFormatter.getTemplate(mockTemplateName))
                .thenReturn("{\"name\": \"${name}\", \"age\": ${age}}");

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            sdjwt.createCredential(templateParams, mockTemplateName);
        });

        assertEquals(ErrorConstants.SD_CLAIMS_PARSE_ERROR, exception.getErrorCode());
        assertTrue(exception.getMessage().contains("SD-Claim path '$.invalid_claim' not found in the issued credential."));
    }

    @Test
    public void should_throwCertifyException_when_sdClaimPathIsMalformed() {
        // The template declares "name", so the optional-field fallback would accept these by their
        // field name alone, and name would be issued without being selectively disclosable.
        String mockTemplateName = "mockTemplate";
        when(mockFormatter.format(any(Map.class))).thenReturn("{\"name\": \"John\"}");

        for (String path : Arrays.asList("name", "$.name[-1]")) {
            when(mockFormatter.getSelectiveDisclosureInfo(mockTemplateName)).thenReturn(Arrays.asList(path));

            CertifyException exception = assertThrows(CertifyException.class,
                    () -> sdjwt.createCredential(new HashMap<>(), mockTemplateName));

            assertEquals(ErrorConstants.SD_CLAIMS_PARSE_ERROR, exception.getErrorCode());
            assertTrue(exception.getMessage().contains("SD-Claim path '" + path + "' is not a valid JSON path."));
        }
        verify(mockFormatter, never()).getTemplate(mockTemplateName);
    }

    @Test
    public void should_issueWithoutTheClaim_when_optionalSdFieldIsMissingForThisHolder() {
        // The template emits nickname only #if the holder has one. This holder has none, so the
        // path is absent from their credential, but the configuration is not wrong.
        String mockTemplateName = "mockTemplate";
        when(mockFormatter.format(any(Map.class))).thenReturn("{\"name\": \"John\"}");
        when(mockFormatter.getSelectiveDisclosureInfo(mockTemplateName))
                .thenReturn(Arrays.asList("$.name", "$.nickname"));
        when(mockFormatter.getTemplate(mockTemplateName))
                .thenReturn("{\"name\": \"${name}\" #if($nickname), \"nickname\": \"${nickname}\"#end}");

        String result = sdjwt.createCredential(new HashMap<>(), mockTemplateName);

        // One disclosure, for name: nickname has nothing to disclose for this holder.
        assertEquals(2, result.split("~", -1).length - 1);
    }

    @Test
    public void should_throwCertifyException_when_onlyAFieldOfTheSameNameUnderAnotherObjectIsInTheTemplate() {
        // street is declared under office, not address, so a missing $.address.street is a wrong
        // path, not an optional field, and must not be dropped silently.
        String mockTemplateName = "mockTemplate";
        when(mockFormatter.format(any(Map.class))).thenReturn("{\"office\": {\"street\": \"Main St\"}, \"address\": {\"city\": \"Pune\"}}");
        when(mockFormatter.getSelectiveDisclosureInfo(mockTemplateName)).thenReturn(Arrays.asList("$.address.street"));
        when(mockFormatter.getTemplate(mockTemplateName))
                .thenReturn("{\"office\": {\"street\": \"${officeStreet}\"}, \"address\": {\"city\": \"${city}\"}}");

        CertifyException exception = assertThrows(CertifyException.class,
                () -> sdjwt.createCredential(new HashMap<>(), mockTemplateName));

        assertEquals(ErrorConstants.SD_CLAIMS_PARSE_ERROR, exception.getErrorCode());
        assertTrue(exception.getMessage().contains("SD-Claim path '$.address.street' not found in the issued credential."));
    }

    @Test
    public void should_issueWithoutTheClaim_when_optionalNestedSdFieldIsMissingForThisHolder() {
        String mockTemplateName = "mockTemplate";
        when(mockFormatter.format(any(Map.class))).thenReturn("{\"address\": {\"city\": \"Pune\"}}");
        when(mockFormatter.getSelectiveDisclosureInfo(mockTemplateName))
                .thenReturn(Arrays.asList("$.address.city", "$.address.street"));
        when(mockFormatter.getTemplate(mockTemplateName))
                .thenReturn("{\"address\": {\"city\": \"${city}\"#if($street), \"street\": \"${street}\"#end}}");

        assertNotNull(sdjwt.createCredential(new HashMap<>(), mockTemplateName));
    }

    @Test
    public void should_throwCertifyException_when_sdPathExpectsAnArrayButTheValueIsAString() {
        // name is declared in the template, so the optional-field fallback would accept $.name[*] and
        // name would be issued as a plain, readable claim instead of a selectively disclosable one.
        String mockTemplateName = "mockTemplate";
        when(mockFormatter.format(any(Map.class))).thenReturn("{\"name\": \"John\"}");
        when(mockFormatter.getSelectiveDisclosureInfo(mockTemplateName)).thenReturn(Arrays.asList("$.name[*]"));

        CertifyException exception = assertThrows(CertifyException.class,
                () -> sdjwt.createCredential(new HashMap<>(), mockTemplateName));

        assertEquals(ErrorConstants.SD_CLAIMS_PARSE_ERROR, exception.getErrorCode());
        assertTrue(exception.getMessage().contains("SD-Claim path '$.name[*]' does not match the structure of the issued credential."));
        verify(mockFormatter, never()).getTemplate(mockTemplateName);
    }

    @Test
    public void should_issueWithoutTheClaim_when_objectWildcardHasNoKeysForThisHolder() {
        String mockTemplateName = "mockTemplate";
        when(mockFormatter.format(any(Map.class))).thenReturn("{\"name\": \"John\", \"address\": {}}");
        when(mockFormatter.getSelectiveDisclosureInfo(mockTemplateName)).thenReturn(Arrays.asList("$.address.*"));
        when(mockFormatter.getTemplate(mockTemplateName))
                .thenReturn("{\"name\": \"${name}\", \"address\": {#if($street)\"street\": \"${street}\"#end}}");

        assertNotNull(sdjwt.createCredential(new HashMap<>(), mockTemplateName));
    }

    @Test
    public void should_issueWithoutTheClaim_when_sdArrayIsEmptyForThisHolder() {
        String mockTemplateName = "mockTemplate";
        when(mockFormatter.format(any(Map.class))).thenReturn("{\"name\": \"John\", \"nationalities\": []}");
        when(mockFormatter.getSelectiveDisclosureInfo(mockTemplateName))
                .thenReturn(Arrays.asList("$.nationalities[*]"));
        when(mockFormatter.getTemplate(mockTemplateName))
                .thenReturn("{\"name\": \"${name}\", \"nationalities\": ${nationalities}}");

        assertNotNull(sdjwt.createCredential(new HashMap<>(), mockTemplateName));
    }

    @Test
    public void should_throwCertifyException_when_templatedJsonIsMalformed() throws JsonProcessingException {
        String mockTemplateName = "badTemplate";
        Map<String, Object> templateParams = new HashMap<>();

        when(mockFormatter.format(any(Map.class))).thenReturn("{invalid json}");
        when(mockFormatter.getSelectiveDisclosureInfo(mockTemplateName)).thenReturn(Arrays.asList("$.invalid"));

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            sdjwt.createCredential(templateParams, mockTemplateName);
        });

        assertEquals(ErrorConstants.JSON_PROCESSING_ERROR, exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Failed to process JSON during SD-JWT creation."));
    }

    @Test
    public void testAddProof_ShouldReplaceUnsignedHeaderWithSignedJWT() {
        String unsignedVC = "header.payload~disclosure";
        String signedJwt = "signed.header.payload";

        JWTSignatureResponseDto signedResponse = new JWTSignatureResponseDto();
        signedResponse.setJwtSignedData(signedJwt);

        when(mockSignatureService.jwsSignV2(any(JWSSignatureRequestDtoV2.class))).thenReturn(signedResponse);

        VCResult<?> result = sdjwt.addProof(unsignedVC, null, "RS256", "appID", "refID", "url", "Ed25519Signature2020");

        assertNotNull(result);
        assertTrue(((String) result.getCredential()).startsWith("signed.header.payload"));
    }

    @Test
    public void testAddProof_ShouldSendCorrectSignatureRequest() {
        String unsignedVC = "header.payload~disclosure";

        JWTSignatureResponseDto response = new JWTSignatureResponseDto();
        response.setJwtSignedData("signed.jwt");
        when(mockSignatureService.jwsSignV2(any(JWSSignatureRequestDtoV2.class))).thenReturn(response);

        sdjwt.addProof(unsignedVC, null, "PS256", "myApp", "myRef", "https://example.com", "Ed25519Signature2020");

        verify(mockSignatureService).jwsSignV2(argThat(dto ->
                "myApp".equals(dto.getApplicationId()) &&
                        "myRef".equals(dto.getReferenceId()) &&
                        "PS256".equals(dto.getSignAlgorithm()) &&
                        dto.getIncludePayload() &&
                        dto.getIncludeCertificateChain() &&
                        "".equals(dto.getCertificateUrl())
        ));
    }
}
