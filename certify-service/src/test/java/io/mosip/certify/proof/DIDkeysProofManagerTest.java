package io.mosip.certify.proof;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import io.ipfs.multibase.Multibase;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

public class DIDkeysProofManagerTest {

    @Test
    void testGetKeyFromHeader_WhenJWKIsNotNull() {
        // Mock JWSHeader
        JWSHeader header = Mockito.mock(JWSHeader.class);
        JWK mockJWK = Mockito.mock(JWK.class);
        when(header.getJWK()).thenReturn(mockJWK);
        // Test
        DIDkeysProofManager manager = new DIDkeysProofManager();
        Optional<JWK> result = manager.getKeyFromHeader(header);

        // Assert
        assertTrue(result.isPresent());
        assertEquals(mockJWK, result.get());
    }

    @Test
    void testGetKeyFromHeader_WhenKeyIDIsEd25519() {
        // Mock JWSHeader
        JWSHeader header = Mockito.mock(JWSHeader.class);
        String keyID = "did:key:z6MktwAJhFN5fDccQ8k1nDtcTAhaW6YuvVcV5xmjKXH9E6zi";
        when(header.getKeyID()).thenReturn(keyID);

        // Decode the keyID to match the expected format
        byte[] decodedKey = Multibase.decode(keyID.split("did:key:")[1]);
        assertEquals((byte) 0xed, decodedKey[0]);
        assertEquals((byte) 0x01, decodedKey[1]);

        // Test
        DIDkeysProofManager manager = new DIDkeysProofManager();
        JWK result = manager.getKeyFromHeader(header).get();

        // Assert
        assertNotNull(result);
        assertEquals("OKP", result.getKeyType().getValue());
        assertEquals("1yljzLGYqiHvJxrd0I7_OT7hb-OLqLqqeWxSwJ50m88", ((OctetKeyPair) result).getX().toString());
    }

    /**
     * ref: https://w3c-ccg.github.io/did-key-spec/#secp256k1
     */
    @Test
    void testGetKeyFromHeader_secp256k1() {
        JWSHeader header = Mockito.mock(JWSHeader.class);
        String keyID = "did:key:zQ3shsijT3Dmb494bwbLqj89Huo6QdYA8U6Xeo391cspCuC1s";
        /*
        {"kty":"EC","crv":"secp256k1","x":"wldSvS-mIkLtxWUKTzH2bzpRc3r-lBeSu0FtqWBKiO4","y":"omtLUrNAYHypnICk14EsyCbHmVQxBCsGf_n3Z2AAnQc"}
         */
        when(header.getKeyID()).thenReturn(keyID);

        // Decode the keyID to match the expected format
        byte[] decodedKey = Multibase.decode(keyID.split("did:key:")[1]);
        // https://w3c-ccg.github.io/did-key-spec/#signature-method-creation-algorithm
        assertEquals((byte) 0xe7, decodedKey[0]);

        // Test
        DIDkeysProofManager manager = new DIDkeysProofManager();
        JWK result = manager.getKeyFromHeader(header).get();

        // Assert
        assertEquals("EC", result.getKeyType().getValue());
    }

    @Test
    void testGetKeyFromHeader_p256() {
        // TODO: should be 0x1200 instead
        JWSHeader header = Mockito.mock(JWSHeader.class);
        // How will the DID differ when the value is compressed vs uncompressed?
        String keyID = "did:key:zDnaehKu2hNcmLBhd5iNkh3v6Q4ncq75fT4EXKMtietgzR1bZ"; // Valid EC key ID for below key
        // {"kty":"EC","crv":"P-256","x":"_NFlbCGfY7ubCwtHA_oEz-vKF5lyg4-cQCYkwl1R8DY",
        //  "y":"a8QxsUe8KdlHv2VQG3CNwB5f1_PHtd41_hhZ8X0QJDM"}
        when(header.getKeyID()).thenReturn(keyID);

        byte[] decodedKey = Multibase.decode(keyID.split("did:key:")[1]); // 0x12 0x00
        assertEquals((byte) 0x80, decodedKey[0]);
        //assertEquals((byte) 0x12, decodedKey[0]);
        //assertEquals((byte) 0x00, decodedKey[1]);

        // Test
        DIDkeysProofManager manager = new DIDkeysProofManager();
        JWK result = manager.getKeyFromHeader(header).get();

        // Assert
        assertNotNull(result);
        assertEquals("EC", result.getKeyType().getValue());
    }

    /*
    @Test
    void testGetKeyFromHeader_WhenKeyIDIsRSA() {
        // Mock JWSHeader
        JWSHeader header = Mockito.mock(JWSHeader.class);
        String keyID = "did:key:z4MXj1wBzi9jUstyPMS4jQqB6KdJaiatPkAtVtGc6bQEQEEsKTic4G7Rou3iBf9vPmT5dbkm9qsZsuVNjq8HCuW1w24nhBFGkRE4cd2Uf2tfrB3N7h4mnyPp1BF3ZttHTYv3DLUPi1zMdkULiow3M1GfXkoC6DoxDUm1jmN6GBj22SjVsr6dxezRVQc7aj9TxE7JLbMH1wh5X3kA58H3DFW8rnYMakFGbca5CB2Jf6CnGQZmL7o5uJAdTwXfy2iiiyPxXEGerMhHwhjTA1mKYobyk2CpeEcmvynADfNZ5MBvcCS7m3XkFCMNUYBS9NQ3fze6vMSUPsNa6GVYmKx2x6JrdEjCk3qRMMmyjnjCMfR4pXbRMZa3i"; // Replace with a valid RSA key ID
        when(header.getKeyID()).thenReturn(keyID);

        // Decode the keyID to match the expected format
        byte[] decodedKey = Multibase.decode(keyID.split("did:key:")[1]);
        assertEquals((byte) 0x85, decodedKey[0]);
        assertEquals((byte) 0x24, decodedKey[1]);

        // Test
        DIDkeysProofManager manager = new DIDkeysProofManager();
        JWK result = manager.getKeyFromHeader(header).get();

        // Assert
        assertNotNull(result);
        assertEquals("RSA", result.getKeyType().getValue());
    }

    @Test
    void testGetKeyFromHeader_WhenKeyIDIsRSA2() throws NoSuchAlgorithmException {
        // Mock JWSHeader
        JWSHeader header = Mockito.mock(JWSHeader.class);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair k = kpg.generateKeyPair();
        byte b[] = k.getPublic().getEncoded();
        String buf = Multibase.encode(Multibase.Base.Base58BTC, b);
        String keyID = "did:key:" + buf;
        RSAPublicKey publicKey = (RSAPublicKey) k.getPublic();
        RSAKey rsaKey = new RSAKey.Builder(publicKey).build();
        System.out.println(rsaKey.toPublicJWK());
        when(header.getKeyID()).thenReturn(keyID);

        // Decode the keyID to match the expected format
        byte[] decodedKey = Multibase.decode(keyID.split("did:key:")[1]);
        assertEquals((byte) 0x12, decodedKey[0]);

        // Test
        DIDkeysProofManager manager = new DIDkeysProofManager();
        JWK result = manager.getKeyFromHeader(header).get();

        // Assert
        assertNotNull(result);
        assertEquals("RSA", result.getKeyType().getValue());
    }
     */
}

