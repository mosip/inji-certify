package io.mosip.certify.proofgenerators.dip;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.kernel.signature.dto.SignRequestDtoV2;
import io.mosip.kernel.signature.dto.SignResponseDto;
import io.mosip.kernel.signature.service.SignatureServicev2;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.security.GeneralSecurityException;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class KeymanagerByteSignerTest {

    @Mock
    private SignatureServicev2 signatureService;
    @Mock
    private KeymanagerByteSigner signer;

    @Before
    public void setUp() {
        signatureService = mock(SignatureServicev2.class);
        signer = new KeymanagerByteSigner("appId", "refId", signatureService, "ES256");
    }

    @Test
    public void testSign_Success() throws Exception {
        byte[] data = "test-data".getBytes();
        String base58Signature = "z3Wv5u"; // valid base58btc prefix

        SignResponseDto response = new SignResponseDto();
        response.setSignature(base58Signature);

        when(signatureService.signv2(any(SignRequestDtoV2.class))).thenReturn(response);

        byte[] result = signer.sign(data);

        assertNotNull(result);
        verify(signatureService).signv2(any(SignRequestDtoV2.class));
    }

    @Test
    public void testSign_MissingAppId_ThrowsException() {
        signer = new KeymanagerByteSigner("", "refId", signatureService, "ES256");
        try {
            signer.sign("abc".getBytes());
            fail("Expected CertifyException");
        } catch (CertifyException ex) {
            assertEquals(ErrorConstants.MISSING_APPLICATION_OR_REFERENCE_ID, ex.getMessage());
        } catch (GeneralSecurityException ex) {
            fail("Expected CertifyException, got GeneralSecurityException");
        }
    }

    @Test
    public void testSign_MissingRefId_ThrowsException() {
        signer = new KeymanagerByteSigner("appId", "", signatureService, "ES256");
        try {
            signer.sign("abc".getBytes());
            fail("Expected CertifyException");
        } catch (CertifyException ex) {
            assertEquals(ErrorConstants.MISSING_APPLICATION_OR_REFERENCE_ID, ex.getMessage());
        } catch (GeneralSecurityException ex) {
            fail("Expected CertifyException, got GeneralSecurityException");
        }
    }
}