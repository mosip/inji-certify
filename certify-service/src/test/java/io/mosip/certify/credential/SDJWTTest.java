package io.mosip.certify.credential;

import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signature.service.SignatureService;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
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

    @InjectMocks
    private SDJWT sdjwt;

    @Before
    public void setup() {
        // MockitoJUnitRunner takes care of injecting mocks
    }

    @Test
    public void testCanHandle_ShouldReturnTrueForCorrectFormat() {
        assertTrue(sdjwt.canHandle("vc+sd-jwt"));
    }

    @Test
    public void testCanHandle_ShouldReturnFalseForIncorrectFormat() {
        assertFalse(sdjwt.canHandle("ld+vc"));
    }

    @Test
    public void testCreateCredential_WithValidInput_ReturnsSdJwt() {
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
    public void testCreateCredential_WithInvalidJson_ReturnsFallbackJwt() {
        String mockTemplateName = "badTemplate";
        Map<String, Object> templateParams = new HashMap<>();

        when(mockFormatter.format(any(Map.class))).thenReturn("{invalid json}");
        when(mockFormatter.getSelectiveDisclosureInfo(mockTemplateName)).thenReturn(Arrays.asList("$.invalid"));

        String result = sdjwt.createCredential(templateParams, mockTemplateName);

        assertNotNull(result);
        String[] parts = result.split("\\.");
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));

        assertTrue(payloadJson.contains("\"none\":\"\""));
    }

    @Test
    public void testAddProof_ShouldReplaceUnsignedHeaderWithSignedJWT() {
        String unsignedVC = "header.payload~disclosure";
        String signedJwt = "signed.header.payload";

        JWTSignatureResponseDto signedResponse = new JWTSignatureResponseDto();
        signedResponse.setJwtSignedData(signedJwt);

        when(mockSignatureService.jwsSign(any(JWSSignatureRequestDto.class))).thenReturn(signedResponse);

        VCResult<?> result = sdjwt.addProof(unsignedVC, null, "RS256", "appID", "refID", "url");

        assertNotNull(result);
        assertTrue(((String) result.getCredential()).startsWith("signed.header.payload"));
    }

    @Test
    public void testAddProof_ShouldSendCorrectSignatureRequest() {
        String unsignedVC = "header.payload~disclosure";

        JWTSignatureResponseDto response = new JWTSignatureResponseDto();
        response.setJwtSignedData("signed.jwt");
        when(mockSignatureService.jwsSign(any(JWSSignatureRequestDto.class))).thenReturn(response);

        sdjwt.addProof(unsignedVC, null, "PS256", "myApp", "myRef", "https://example.com");

        verify(mockSignatureService).jwsSign(argThat(dto ->
                "myApp".equals(dto.getApplicationId()) &&
                        "myRef".equals(dto.getReferenceId()) &&
                        "PS256".equals(dto.getSignAlgorithm()) &&
                        dto.getIncludePayload() &&
                        dto.getIncludeCertificate() &&
                        "".equals(dto.getCertificateUrl())
        ));
    }
}
