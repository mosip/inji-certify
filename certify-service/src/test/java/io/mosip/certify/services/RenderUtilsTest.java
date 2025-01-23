package io.mosip.certify.services;

import io.ipfs.multibase.Multibase;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.InvalidRequestException;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertThrows;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
class RenderUtilsTest {

    @Test
    void getDigestMultibase() {
        String svg = """
               <svg viewBox=".5 .5 3 4" fill="none" stroke="#20b2a" stroke-linecap="round"> <path d=" M1 4h-.001 V1h2v.001 M1 2.6 h1v.001"/> </svg>
                """;
        String actual = CredentialUtils.getDigestMultibase(svg);
        String expected = "z4po9QkJj1fhMt6cxHSnDnAUat4PEVrerUGGsPHLxJnK5";
        assertEquals(expected, actual);
    }

    @Test
    public void testNoSuchAlgorithmException() {
        // Mock the MessageDigest.getInstance() method to throw NoSuchAlgorithmException
        try (MockedStatic<MessageDigest> mockedMessageDigest = Mockito.mockStatic(MessageDigest.class)) {
            mockedMessageDigest.when(() -> MessageDigest.getInstance("SHA-256")).thenThrow(NoSuchAlgorithmException.class);
            String svg = "<svg></svg>";
            assertThrows(RuntimeException.class, () -> CredentialUtils.getDigestMultibase(svg));
        }
    }

}