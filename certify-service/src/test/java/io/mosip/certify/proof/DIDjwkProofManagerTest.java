package io.mosip.certify.proof;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DIDjwkProofManagerTest {

    DIDjwkProofManager manager;
    JWSHeader header;

    @BeforeEach
    public void setUp() {
        header = Mockito.mock(JWSHeader.class);
        manager = new DIDjwkProofManager();
    }

    /**
     * when JWK exists in the header, getKeyFromHeader should return the JWK
     */
    @Test
    void getKeyFromHeader_JWK() {
        when(header.getJWK()).thenReturn(mock(JWK.class));
        manager = new DIDjwkProofManager();
        Optional<JWK> j = manager.getKeyFromHeader(header);
        assertTrue(j.isPresent());
    }

    /**
     * when jwk or kid doesn't exist, it should return null
     */
    @Test
    void getKeyFromHeader_null() {
        when(header.getJWK()).thenReturn(null);
        when(header.getKeyID()).thenReturn(null);
        Optional<JWK> j = manager.getKeyFromHeader(header);
        assertTrue(j.isEmpty());
    }

    @Test
    void getKeyFromHeader_garbage() {
        when(header.getKeyID()).thenReturn("garbage");
        Optional<JWK> j = manager.getKeyFromHeader(header);
        assertTrue(j.isEmpty());
    }

    @Test
    void getKeyFromHeader_garbageJWK() {
        when(header.getKeyID()).thenReturn("did:jwk:garbage");
        Optional<JWK> j = manager.getKeyFromHeader(header);
        assertTrue(j.isEmpty());
    }

    @Test
    void getKeyFromHeader_garbageKID() {
        when(header.getKeyID()).thenReturn("did:jwk:garbage");
        Optional<JWK> j = manager.getKeyFromHeader(header);
        assertTrue(j.isEmpty());
    }

    /**
     * when JWK does not exist in the header, getKeyFromHeader should return the kid
     * iff did:jwk:<key> is present.
     *
     */
    @Test
    void getKeyFromHeader_did() {
        when(header.getKeyID()).thenReturn("");
    }

    @Test
    void getDID() {
    }
}