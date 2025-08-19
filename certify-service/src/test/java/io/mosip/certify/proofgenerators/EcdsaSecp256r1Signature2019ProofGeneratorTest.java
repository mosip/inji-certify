package io.mosip.certify.proofgenerators;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.kernel.signature.dto.SignRequestDtoV2;
import io.mosip.kernel.signature.dto.SignResponseDto;
import io.mosip.kernel.signature.service.SignatureServicev2;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import org.junit.Before;
import org.junit.Test;
import org.mockito.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class EcdsaSecp256r1Signature2019ProofGeneratorTest {

    @InjectMocks
    private EcdsaSecp256r1Signature2019ProofGenerator proofGenerator;

    @Mock
    private SignatureServicev2 signatureService;

    private Map<String, String> keyID;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        keyID = new HashMap<>();
        keyID.put(Constants.APPLICATION_ID, "appId");
        keyID.put(Constants.REFERENCE_ID, "refId");
    }

    @Test
    public void testGetName() {
        assertEquals(SignatureAlg.EC_SECP256R1_2019, proofGenerator.getName());
    }

    @Test
    public void testGetCanonicalizer() {
        Canonicalizer canonicalizer = proofGenerator.getCanonicalizer();
        assertNotNull(canonicalizer);
        assertTrue(canonicalizer instanceof URDNA2015Canonicalizer);
    }

    @Test
    public void testGenerateProof_Success() {
        LdProof baseProof = new LdProof();
        SignResponseDto response = new SignResponseDto();
        response.setSignature("mockSignature");

        when(signatureService.signv2(any(SignRequestDtoV2.class))).thenReturn(response);

        LdProof result = proofGenerator.generateProof(baseProof, "mockEncodedHash", keyID);

        assertNotNull(result);
        assertEquals("mockSignature", result.getProofValue());
        verify(signatureService).signv2(any(SignRequestDtoV2.class));
    }

    @Test
    public void testGenerateProof_NullBaseProof() {
        SignResponseDto response = new SignResponseDto();
        response.setSignature("mockSignature");
        when(signatureService.signv2(any(SignRequestDtoV2.class))).thenReturn(response);

        LdProof result = proofGenerator.generateProof(null, "mockEncodedHash", keyID);

        assertNotNull(result);
        assertEquals("mockSignature", result.getProofValue());
    }

    @Test
    public void testGenerateProof_EmptyKeyID() {
        Map<String, String> emptyKeyID = new HashMap<>();
        SignResponseDto response = new SignResponseDto();
        response.setSignature("mockSignature");
        when(signatureService.signv2(any(SignRequestDtoV2.class))).thenReturn(response);

        LdProof result = proofGenerator.generateProof(new LdProof(), "mockEncodedHash", emptyKeyID);

        assertNotNull(result);
        assertEquals("mockSignature", result.getProofValue());
    }

    @Test
    public void testGenerateProof_VerifySignRequestDtoV2Fields() {
        SignResponseDto response = new SignResponseDto();
        response.setSignature("mockSignature");
        ArgumentCaptor<SignRequestDtoV2> captor = ArgumentCaptor.forClass(SignRequestDtoV2.class);
        when(signatureService.signv2(any(SignRequestDtoV2.class))).thenReturn(response);

        proofGenerator.generateProof(new LdProof(), "mockEncodedHash", keyID);

        verify(signatureService).signv2(captor.capture());
        SignRequestDtoV2 dto = captor.getValue();
        assertEquals("mockEncodedHash", dto.getDataToSign());
        assertEquals("appId", dto.getApplicationId());
        assertEquals("refId", dto.getReferenceId());
        assertEquals("base58btc", dto.getResponseEncodingFormat());
        assertEquals("ES256", dto.getSignAlgorithm());
    }
}