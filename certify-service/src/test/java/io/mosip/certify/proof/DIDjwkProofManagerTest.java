package io.mosip.certify.proof;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
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
        assertFalse(j.isEmpty());
    }

    /**
     * when jwk or kid doesn't exist, it should return an empty object
     */
    @Test
    void getKeyFromHeader_null() {
        when(header.getJWK()).thenReturn(null);
        when(header.getKeyID()).thenReturn(null);
        Optional<JWK> j = manager.getKeyFromHeader(header);
        assertTrue(j.isEmpty());
    }

    /**
     * when JWK does not exist in the header and an invalid kid is present
     *  getKeyFromHeader should return an empty object
     */
    @Test
    void getKeyFromHeader_garbage() {
        when(header.getKeyID()).thenReturn("garbage");
        Optional<JWK> j = manager.getKeyFromHeader(header);
        assertTrue(j.isEmpty());
    }

    /**
     * when JWK does not exist in the header, getKeyFromHeader should return the kid
     */
    @Test
    void getKeyFromHeader_garbageJWK() {
        when(header.getKeyID()).thenReturn("did:jwk:garbage");
        Optional<JWK> j = manager.getKeyFromHeader(header);
        assertTrue(j.isEmpty());
    }

    @Test
    void getKeyFromHeader_garbageKID() {
        when(header.getKeyID()).thenReturn("did:kid:garbage");
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
    void getDID_didjwk() throws NoSuchAlgorithmException {
        RSAKey rsaJWK = getRsaKey();
        when(header.getJWK()).thenReturn(rsaJWK);
        Optional<String> did = manager.getDID(header);
        assertTrue(did.isPresent());
        assertTrue(did.get().startsWith("did:jwk"));
    }
    @Test
    void getDID_didjwk_keyid() throws NoSuchAlgorithmException {
        RSAKey rsaJWK = getRsaKey();
        byte[] keyBytes = rsaJWK.toJSONString().getBytes(StandardCharsets.UTF_8);
        String didJWK = "did:jwk:" + Base64.getUrlEncoder().encodeToString(keyBytes);
        // convert the rsaJWK to a did:jwk and remove the JWK
        when(header.getKeyID()).thenReturn(didJWK);
        assertEquals(didJWK, manager.getDID(header).get());
        assertTrue(didJWK.startsWith("did:jwk:"));
    }

    // TODO: implement this for did:key:<RSA-pub-key>

    private static RSAKey getRsaKey() throws NoSuchAlgorithmException {
        // Generate an RSA Keypair and make it into a JWK
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        RSAKey rsaJWK = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyID("123")
                .build();
        return rsaJWK;
    }

}