package io.mosip.certify.credential;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDtoV2;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signature.service.SignatureService;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

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

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private SDJWT sdjwt;

    @Before
    public void setup() {
        // MockitoJUnitRunner takes care of injecting mocks
        MockitoAnnotations.openMocks(this);
        ReflectionTestUtils.setField(sdjwt, "objectMapper", objectMapper);
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
    public void testCreateCredential_WithValidInput_ReturnsSdJwt() throws JsonProcessingException {
        String mockTemplateName = "mockTemplate";
        Map<String, Object> templateParams = new HashMap<>();

        String templateJson = "{\"name\": \"John\", \"age\": 30}";
        JsonNode mockJsonNode =  mock(JsonNode.class);
        when(mockFormatter.format(any(Map.class))).thenReturn(templateJson);
        when(mockFormatter.getSelectiveDisclosureInfo(mockTemplateName))
                .thenReturn(Arrays.asList("$.name"));
        when(objectMapper.readTree(templateJson)).thenReturn(mockJsonNode);

        String result = sdjwt.createCredential(templateParams, mockTemplateName);

        assertNotNull(result);
        assertTrue(result.contains("~"));
    }

    @Test
    public void testCreateCredential_WithInvalidJson_ReturnsFallbackJwt() throws JsonProcessingException {
        String mockTemplateName = "badTemplate";
        Map<String, Object> templateParams = new HashMap<>();

        when(mockFormatter.format(any(Map.class))).thenReturn("{invalid json}");
        when(mockFormatter.getSelectiveDisclosureInfo(mockTemplateName)).thenReturn(Arrays.asList("$.invalid"));
        when(objectMapper.readTree("{invalid json}")).thenThrow(new JsonProcessingException("Invalid JSON") {});

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            sdjwt.createCredential(templateParams, mockTemplateName);
        });

        assertEquals("JSON_PROCESSING_ERROR", exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Error processing JSON for SDJWT creation"));
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
