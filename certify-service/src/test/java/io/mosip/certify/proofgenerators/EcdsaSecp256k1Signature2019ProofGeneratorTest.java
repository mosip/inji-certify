package io.mosip.certify.proofgenerators;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.certify.proofgenerators.EcdsaSecp256k1Signature2019ProofGenerator;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signature.service.SignatureService;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class EcdsaSecp256k1Signature2019ProofGeneratorTest {

    @InjectMocks
    private EcdsaSecp256k1Signature2019ProofGenerator proofGenerator;

    @Mock
    private SignatureService signatureService;

    private Map<String, String> keyID;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        keyID = new HashMap<>();
        keyID.put(Constants.APPLICATION_ID, "app789");
        keyID.put(Constants.REFERENCE_ID, "ref012");
    }

    @Test
    public void testGetName() {
        assertEquals(SignatureAlg.EC_SECP256K1_2019, proofGenerator.getName());
    }

    @Test
    public void testGetCanonicalizer() {
        Canonicalizer canonicalizer = proofGenerator.getCanonicalizer();
        assertNotNull(canonicalizer);
        assertTrue(canonicalizer instanceof URDNA2015Canonicalizer);
    }

    @Test
    public void testGenerateProofSuccess() {
        LdProof baseProof = new LdProof();
        JWTSignatureResponseDto response = new JWTSignatureResponseDto();
        response.setJwtSignedData("mockJWS-2019");

        when(signatureService.jwsSign(any(JWSSignatureRequestDto.class))).thenReturn(response);

        LdProof result = proofGenerator.generateProof(baseProof, "mockEncodedHash", keyID);

        assertNotNull(result);
        assertEquals("mockJWS-2019", result.getJws());
        verify(signatureService).jwsSign(any(JWSSignatureRequestDto.class));
    }

    @Test
    public void testGenerateProof_NullProof() {
        JWTSignatureResponseDto response = new JWTSignatureResponseDto();
        response.setJwtSignedData("mockJWS-2019");
        when(signatureService.jwsSign(any(JWSSignatureRequestDto.class))).thenReturn(response);

        LdProof result = proofGenerator.generateProof(null, "mockEncodedHash", keyID);

        assertNotNull(result);
        assertEquals("mockJWS-2019", result.getJws());
    }

    @Test
    public void testGenerateProof_EmptyKeyID() {
        Map<String, String> emptyKeyID = new HashMap<>();
        JWTSignatureResponseDto response = new JWTSignatureResponseDto();
        response.setJwtSignedData("mockJWS-2019");

        when(signatureService.jwsSign(any(JWSSignatureRequestDto.class))).thenReturn(response);

        LdProof result = proofGenerator.generateProof(new LdProof(), "mockEncodedHash", emptyKeyID);

        assertNotNull(result);
        assertEquals("mockJWS-2019", result.getJws());
    }
}
