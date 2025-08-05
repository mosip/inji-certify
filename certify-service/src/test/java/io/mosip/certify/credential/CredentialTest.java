package io.mosip.certify.credential;

import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.credential.Credential;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signature.service.SignatureService;
import io.mosip.certify.vcformatters.VCFormatter;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class CredentialTest {

    private VCFormatter mockFormatter;
    private SignatureService mockSignatureService;
    private Credential credential;

    @Before
    public void setUp() {
        mockFormatter = mock(VCFormatter.class);
        mockSignatureService = mock(SignatureService.class);

        // Minimal subclass of Credential to allow testing
        credential = new Credential(mockFormatter, mockSignatureService) {
            @Override
            public boolean canHandle(String format) {
                return false;
            }
        };
    }

    @Test
    public void testAddProofInBaseCredentialClass() {
        JWTSignatureResponseDto responseDto = new JWTSignatureResponseDto();
        responseDto.setJwtSignedData("signed.jwt.token");

        when(mockSignatureService.jwsSign(any(JWSSignatureRequestDto.class)))
                .thenReturn(responseDto);

        VCResult<?> result = credential.addProof(
                "unsignedVC",
                null,
                "RS256",
                "testAppId",
                "testRefId",
                "https://example.com/pubkey",
                "Ed25519Signature2020"
        );

        assertNotNull(result);
        assertEquals("vc", result.getFormat());
        assertEquals("signed.jwt.token", result.getCredential());
    }
}
