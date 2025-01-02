package io.mosip.certify.proofgenerators;

import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.kernel.signature.dto.SignRequestDtoV2;
import io.mosip.kernel.signature.dto.SignResponseDto;
import io.mosip.kernel.signature.service.SignatureServicev2;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ConditionalOnProperty(name = "mosip.certify.data-provider-plugin.issuer.vc-sign-algo", havingValue = SignatureAlg.ED25519_SIGNATURE_SUITE_2020)
class Ed25519Signature2020ProofGeneratorTest {

    @InjectMocks
    private Ed25519Signature2020ProofGenerator proofGenerator;

    @Mock
    private SignatureServicev2 signatureService;

    private Map<String, String> keyID;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        keyID = new HashMap<>();
        keyID.put(Constants.APPLICATION_ID, "app123");
        keyID.put(Constants.REFERENCE_ID, "ref456");
    }

    @Test
    void testGetName() {
        assertEquals("Ed25519Signature2020", proofGenerator.getName());
    }

    @Test
    void testGetCanonicalizer() {
        Canonicalizer canonicalizer = proofGenerator.getCanonicalizer();
        assertNotNull(canonicalizer);
        assertTrue(canonicalizer instanceof URDNA2015Canonicalizer);
    }

    @Test
    void testGenerateProofSuccess() {
        LdProof baseProof = new LdProof();
        String vcEncodedHash = "mockEncodedHash";
        SignResponseDto responseDto = new SignResponseDto();
        responseDto.setSignature("mockSignatureValue");

        when(signatureService.signv2(any(SignRequestDtoV2.class))).thenReturn(responseDto);

        LdProof result = proofGenerator.generateProof(baseProof, vcEncodedHash, keyID);

        assertNotNull(result);
        assertEquals("mockSignatureValue", result.getProofValue());

        ArgumentCaptor<SignRequestDtoV2> captor = ArgumentCaptor.forClass(SignRequestDtoV2.class);
        verify(signatureService).signv2(captor.capture());

        SignRequestDtoV2 capturedPayload = captor.getValue();
        assertEquals(vcEncodedHash, capturedPayload.getDataToSign());
        assertEquals("app123", capturedPayload.getApplicationId());
        assertEquals("ref456", capturedPayload.getReferenceId());
        assertEquals("base58btc", capturedPayload.getResponseEncodingFormat());
    }

    @Test
    void testGenerateProof_NullProof() {
        SignResponseDto responseDto = new SignResponseDto();
        responseDto.setSignature("mockSignatureValue");
        when(signatureService.signv2(any(SignRequestDtoV2.class))).thenReturn(responseDto);

        LdProof result = proofGenerator.generateProof(null, "mockEncodedHash", keyID);

        assertNotNull(result);
        assertEquals("mockSignatureValue", result.getProofValue());
    }

    @Test
    void testGenerateProof_EmptyKeyID() {
        SignResponseDto responseDto = new SignResponseDto();
        responseDto.setSignature("mockSignatureValue");
        when(signatureService.signv2(any(SignRequestDtoV2.class))).thenReturn(responseDto);

        Map<String, String> emptyKeyID = new HashMap<>();
        LdProof result = proofGenerator.generateProof(new LdProof(), "mockEncodedHash", emptyKeyID);

        assertNotNull(result);
        assertEquals("mockSignatureValue", result.getProofValue());
    }

    @Test
    void testGenerateProofSignature_ServiceFailure() {
        when(signatureService.signv2(any(SignRequestDtoV2.class))).thenThrow(new RuntimeException("Signature Failed"));

        Exception exception = assertThrows(RuntimeException.class, () -> {
            proofGenerator.generateProof(new LdProof(), "mockEncodedHash", keyID);
        });

        assertEquals("Signature Failed", exception.getMessage());
    }
}