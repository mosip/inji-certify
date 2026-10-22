package io.mosip.certify.credential;

import io.mosip.certify.credential.Credential;
import io.mosip.certify.credential.CredentialFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Arrays;
import java.util.Optional;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class CredentialFactoryTest {

    private CredentialFactory credentialFactory;
    private Credential mockCredential;

    @Before
    public void setUp() {
        mockCredential = mock(Credential.class);
        credentialFactory = new CredentialFactory(Arrays.asList(mockCredential));
    }

    @Test
    public void testGetCredentialWhenCanHandleReturnsTrue() {
        when(mockCredential.canHandle("ldp_vc")).thenReturn(true);

        Optional<Credential> result = credentialFactory.getCredential("ldp_vc");

        assertTrue(result.isPresent());
        assertEquals(mockCredential, result.get());
    }

    @Test
    public void testGetCredentialWhenFormatIsNull() {
        Optional<Credential> result = credentialFactory.getCredential(null);

        assertFalse(result.isPresent());
    }

    @Test
    public void testGetCredentialWhenNoCredentialMatches() {
        when(mockCredential.canHandle("unknown_format")).thenReturn(false);

        Optional<Credential> result = credentialFactory.getCredential("unknown_format");

        assertFalse(result.isPresent());
    }
}
