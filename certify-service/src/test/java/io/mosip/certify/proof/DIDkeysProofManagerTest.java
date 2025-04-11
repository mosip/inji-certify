package io.mosip.certify.proof;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.ipfs.multibase.Multibase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Date;
import java.util.Optional;
import java.util.UUID;

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
        assertEquals("wldSvS-mIkLtxWUKTzH2bzpRc3r-lBeSu0FtqWBKiO4", ((ECKey) result).getX().toString());
        assertEquals("omtLUrNAYHypnICk14EsyCbHmVQxBCsGf_n3Z2AAnQc", ((ECKey) result).getY().toString());
    }

    @Test
    void testGetKeyFromHeader_p256() {
        // 0x8024 is the variable integer
        JWSHeader header = Mockito.mock(JWSHeader.class);
        // How will the DID differ when the value is compressed vs uncompressed?
        String keyID = "did:key:zDnaehKu2hNcmLBhd5iNkh3v6Q4ncq75fT4EXKMtietgzR1bZ"; // Valid EC key ID for below key
        // {"kty":"EC","crv":"P-256","x":"_NFlbCGfY7ubCwtHA_oEz-vKF5lyg4-cQCYkwl1R8DY",
        //  "y":"a8QxsUe8KdlHv2VQG3CNwB5f1_PHtd41_hhZ8X0QJDM"}
        when(header.getKeyID()).thenReturn(keyID);

        byte[] decodedKey = Multibase.decode(keyID.split("did:key:")[1]); // 0x12 0x00
        assertEquals((byte) 0x80, decodedKey[0]);
        assertEquals((byte) 0x24, decodedKey[1]);

        // Test
        DIDkeysProofManager manager = new DIDkeysProofManager();
        JWK result = manager.getKeyFromHeader(header).get();

        // Assert
        assertNotNull(result);
        assertEquals("EC", result.getKeyType().getValue());
        assertEquals("-wim35fhXPUsGq78EeP90JV1Fq0YvvYTbc_0kqhB6cQ", ((ECKey) result).getX().toString());
        assertEquals("42YsvtOfjrHASU_mJTraPLeEuA-At3YsXQwbRZDpM_A", ((ECKey) result).getY().toString());
    }

    @Test
    void testGetKeyFromHeader_RSA() {
        JWSHeader header = Mockito.mock(JWSHeader.class);
        String keyID = "did:key:z4MXj1wBzi9jUstyPx4gpGCHXGU6SZNCGaWDBktDPabqKE9pU9Y3D8GeMkeXipiM3MYJooZRkhi32m2CWdWVm1MTdYQs2pwtp92SPbLnp9eqDKTwCWNrvnqgsbJC9u6CvrXfUj1XeRZgSEkRxqoAjycSFyAsdrEP76d9NaRveKKabnNQ4y2NCBTY2q8c2tBP4HAGWVa4rMvsgmZY7zcoyf1rLnuAhG717cXdDrrWJnHXY3miMPfHvZbLhouoXcakRDRRnxPJYRCFHqqohSBeDxDqN1QKw77MFCDwz286bWpWWxS1mD4DZwQdBomoQgv5y1LyvndoxHJ4GukM2m8AzJvy5eibDufpJtva6F5cZMq3nKw4hJtnU";
        // {"kty":"RSA","e":"AQAB","use":"sig","kid":"c6e3bcdd-8a87-4bd0-a739-7071b5fa8383",
        // "n":"y6dYuJhvq1gPXDm2ulPepI5RO19Z9i0ZVrWkvebXEZ2R_gUXNpVk7zHa2K-Z_JEX1Vtnrgr9X2bBgsxU57PoPRQIMiVKbV-xPLEfmtuX7sFn2Oucj7_lqI0Nm3wPZ8X0nl5I-Wy-Lug5NGWghEtjbXzF2d2gHRtuZ72_MbYnMBT7qpkK7GizutCMBqmzXASdbxijkApteOe2cMqZprFcnoGSPV_sfD_1eQaFHNCMPJjYOm_L1Mx0M7vLMvbh3mNGlvxWN7gC7m5bgvn_TEBeKDi3OkMGmBbGXsVo7qcCxJrp_eIgahX3YtkzMsjD7CwM_A-H1vl8w_v0KtZZNbLpAw"}
        when(header.getKeyID()).thenReturn(keyID);

        byte[] decodedKey = Multibase.decode(keyID.split("did:key:")[1]); // 0x12 0x00
        assertEquals((byte) 0x85, decodedKey[0]);
        assertEquals((byte) 0x24, decodedKey[1]);

        // Test
        DIDkeysProofManager manager = new DIDkeysProofManager();
        JWK result = manager.getKeyFromHeader(header).get();

        // Assert
        assertNotNull(result);
        assertEquals("RSA", result.getKeyType().getValue());
        assertEquals("AQAB", ((RSAKey) result).getPublicExponent().toString());
        assertEquals("y6dYuJhvq1gPXDm2ulPepI5RO19Z9i0ZVrWkvebXEZ2R_gUXNpVk7zHa2K-Z_JEX1Vtnrgr9X2bBgsxU57PoPRQIMiVKbV-xPLEfmtuX7sFn2Oucj7_lqI0Nm3wPZ8X0nl5I-Wy-Lug5NGWghEtjbXzF2d2gHRtuZ72_MbYnMBT7qpkK7GizutCMBqmzXASdbxijkApteOe2cMqZprFcnoGSPV_sfD_1eQaFHNCMPJjYOm_L1Mx0M7vLMvbh3mNGlvxWN7gC7m5bgvn_TEBeKDi3OkMGmBbGXsVo7qcCxJrp_eIgahX3YtkzMsjD7CwM_A-H1vl8w_v0KtZZNbLpAw",
                ((RSAKey) result).getModulus().toString());
    }

    @Test
    void testGetKeyFromHeader_genKeyP256() throws JOSEException {
        ECKey jwk = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .issueTime(new Date())
                .generate();
        DIDkeysProofManager manager = new DIDkeysProofManager();
        // Create a jwt token with the above jwk in the jws header
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.PS256)
               .jwk(jwk.toPublicJWK())
               .build();
        SignedJWT signedJWT = new SignedJWT(jwsHeader, new JWTClaimsSet.Builder().build());
        JWK actualJWK = manager.getKeyFromHeader(signedJWT.getHeader()).get();
        assertEquals(jwk.toPublicJWK(), actualJWK);
    }



    @Test
    void testGetKeyFromHeader_genEd25519() throws JOSEException {
        OctetKeyPair jwk = new OctetKeyPairGenerator(Curve.Ed25519)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .provider(new BouncyCastleProvider())
                .issueTime(new Date())
                .generate();
        DIDkeysProofManager manager = new DIDkeysProofManager();
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .jwk(jwk.toPublicJWK())
                .build();
        SignedJWT signedJWT = new SignedJWT(jwsHeader, new JWTClaimsSet.Builder().build());
        JWK actualJWK = manager.getKeyFromHeader(signedJWT.getHeader()).get();
        assertEquals(jwk.toPublicJWK(), actualJWK);
    }

    @Test
    void testGetKeyFromHeader_genKeySECPK1() throws JOSEException {
        ECKey jwk = new ECKeyGenerator(Curve.SECP256K1)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .provider(new BouncyCastleProvider())
                .issueTime(new Date())
                .generate();
        DIDkeysProofManager manager = new DIDkeysProofManager();
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .jwk(jwk.toPublicJWK())
                .build();
        SignedJWT signedJWT = new SignedJWT(jwsHeader, new JWTClaimsSet.Builder().build());
        JWK actualJWK = manager.getKeyFromHeader(signedJWT.getHeader()).get();
        assertEquals(jwk.toPublicJWK(), actualJWK);
    }
}

