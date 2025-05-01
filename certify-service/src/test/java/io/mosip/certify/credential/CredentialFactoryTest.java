package io.mosip.certify.credential;

import io.mosip.certify.credential.Credential;
import io.mosip.certify.credential.CredentialFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Arrays;
import java.util.Optional;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class CredentialFactoryTest {

    @InjectMocks
    private CredentialFactory credentialFactory;
    private Credential mockCredential;

    @Before
    public void setUp() {
        credentialFactory = new CredentialFactory();
        mockCredential = mock(Credential.class);

        // Simulate Spring's @Autowired
        ReflectionTestUtils.setField(credentialFactory, "credentials", Arrays.asList(mockCredential));
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
