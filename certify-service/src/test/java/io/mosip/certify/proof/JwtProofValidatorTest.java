package io.mosip.certify.proof;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.mosip.certify.core.dto.CredentialProof;
import io.mosip.certify.core.exception.InvalidRequestException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.*;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

class JwtProofValidatorTest {

    private JwtProofValidator jwtProofValidator;

    @Mock
    private CredentialProof credentialProof;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        jwtProofValidator = new JwtProofValidator();
        ReflectionTestUtils.setField(jwtProofValidator, "supportedAlgorithms", List.of("RS256", "ES256K", "Ed25519"));
        ReflectionTestUtils.setField(jwtProofValidator, "credentialIdentifier", "test-credential-id");
    }

    @Test
    void testValidateWithNullJwt() {

        when(credentialProof.getJwt()).thenReturn(null);


        boolean result = jwtProofValidator.validate("client-id", "nonce", credentialProof);


        assertFalse(result, "Expected validation to fail for null JWT");
    }

    @Test
    void testValidateWithBlankJwt() {

        when(credentialProof.getJwt()).thenReturn("");


        boolean result = jwtProofValidator.validate("client-id", "nonce", credentialProof);


        assertFalse(result, "Expected validation to fail for blank JWT");
    }

    @Test
    void getProofType () {
        String proofType = jwtProofValidator.getProofType();
        assertNotNull(proofType);
        assertEquals("jwt", proofType);
    }

    @Test
    void testValidate_ValidJWT() throws Exception {
        String jwt = createValidJWT();
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setJwt(jwt);

        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof);

        assertTrue(result, "JWT should be valid");
    }

    @Test
    void testValidate_InvalidJWT() {
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setJwt("invalid.jwt.token");

        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof);

        assertFalse(result, "Invalid JWT should fail validation");
    }

    @Test
    void testGetKeyMaterial_ValidJWT() throws Exception {
        String jwt = createValidJWT();
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setJwt(jwt);

        String keyMaterial = jwtProofValidator.getKeyMaterial(credentialProof);
        assertNotNull(keyMaterial);
        assertTrue(keyMaterial.startsWith("did:jwk:"), "Key material should be prefixed with did:jwk");
    }

    @Test
    void testGetKeyMaterial_InvalidJWT() {
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setJwt("invalid.jwt.token");

        assertThrows(InvalidRequestException.class, () -> jwtProofValidator.getKeyMaterial(credentialProof));
    }

    private String createValidJWT() throws Exception {
        // Generate a 2048-bit RSA key pair
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .generate();

        // Extract public key for embedding in the JWT header
        RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(rsaPublicJWK)  // Embed the public JWK
                .build();

        // Build JWT claims
        SignedJWT jwt = new SignedJWT(header, new com.nimbusds.jwt.JWTClaimsSet.Builder()
                .audience("test-credential-id")
                .issuer("test-client")
                .claim("nonce", "test-nonce")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 60000)) // 1 min expiration
                .build());

        // Sign JWT using private key
        JWSSigner signer = new RSASSASigner(rsaJWK);
        jwt.sign(signer);

        return jwt.serialize();
    }

    private String createValidJWTWithDid(String issuer, Long expiryMillis, Boolean validDid ) throws Exception {
        // Generate a 2048-bit RSA key pair
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .generate();

        // Extract public key
        RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

        String didJWK;

        if(validDid)
        // Construct the did:jwk identifier
            didJWK  = "did:jwk:" + Base64.getUrlEncoder().withoutPadding().encodeToString(rsaPublicJWK.toJSONString().getBytes()) + "#0";
        else
            didJWK = "did:jwk:invalid";

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .keyID(didJWK)  // Set kid as did:jwk
                .build();

        // Build JWT claims
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .audience("test-credential-id")
                .claim("nonce", "test-nonce")
                .issueTime(new Date());

        if (issuer != null) {
            claimsBuilder.issuer(issuer);
        }

        if (expiryMillis != null) {
            claimsBuilder.expirationTime(new Date(System.currentTimeMillis() + expiryMillis));
        }

        SignedJWT jwt = new SignedJWT(header, claimsBuilder.build());

        // Sign JWT using private key
        JWSSigner signer = new RSASSASigner(rsaJWK);
        jwt.sign(signer);

        return jwt.serialize();
    }

    @Test
    public  void testValidate_DIDJWK_ValidJWT_WithClientID_and_Expiry() throws Exception {
        String jwt = createValidJWTWithDid("test-client", 60000L, true);
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setJwt(jwt);

        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof);

        assertTrue(result, "JWT should be valid");
    }

    @Test
    public  void testValidate_DIDJWK_ValidJWT_NoClientID_and_Expiry() throws Exception {
        String jwt = createValidJWTWithDid(null, 60000L, true);
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setJwt(jwt);

        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof);

        assertTrue(result, "JWT should be valid");
    }

    @Test
    public  void testValidate_DIDJWK_ValidJWT_NoClientID_and_No_Expiry() throws Exception {
        String jwt = createValidJWTWithDid(null, null, true);
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setJwt(jwt);

        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof);

        assertTrue(result, "JWT should be valid");
    }
    @Test
    public  void testValidate_DIDJWK_ValidJWT_WrongClientID() throws Exception {
        String jwt = createValidJWTWithDid("client-id-1", 600000L, true);
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setJwt(jwt);

        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof);

        assertFalse(result, "Client id should match");
    }

    @Test
    public void testValidate_InvalidDID_JWK()  {
        String jwt = null;
        try {
            jwt = createValidJWTWithDid("test-client", 60000L, false);
        } catch (Exception e) {
            //do nothing here
        }
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setJwt(jwt);
        //exception are handled by the validator logic presently
        assertFalse( jwtProofValidator.validate("test-client", "test-nonce", credentialProof));

    }

    @Test
    public void testValidate_InvalidJwt_MissingClaims() throws JOSEException {
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .generate();

        // Extract public key for embedding in the JWT header
        RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(rsaPublicJWK)  // Embed the public JWK
                .build();

        // Build JWT claims
        SignedJWT jwt = new SignedJWT(header, new com.nimbusds.jwt.JWTClaimsSet.Builder()
                .audience("test-credential-id")
                .issuer("test-client")
                .claim("nonce", "test-nonce")
                .expirationTime(new Date(System.currentTimeMillis() + 60000)) // 1 min expiration
                .build());

        // Sign JWT using private key
        JWSSigner signer = new RSASSASigner(rsaJWK);
        jwt.sign(signer);

        String jwtStr = jwt.serialize();
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setJwt(jwtStr);
        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof);
        assertFalse(result, "Missing iat from jwt claims");
    }

    @Test
    public void testValidate_Es256_InvalidAlgException() throws ParseException, JOSEException {
        // Generate a valid ECKey with ES256
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();

        // Create a public JWK from the private JWK
        JWK publicJwk = ecJWK.toPublicJWK();

        // Create JWS Header with public JWK
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .jwk(publicJwk)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .build();

        // Build JWT Claims
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("test-credential-id")
                .issuer("clientId")
                .claim("nonce", "someNonce")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 3600000)) // 1 hour from now
                .build();

        // Create and sign the JWT with the private EC key
        SignedJWT signedJWT = new SignedJWT(header, claims);
        JWSSigner signer = new ECDSASigner(ecJWK);
        signedJWT.sign(signer);

        // Serialize JWT
        String jwt = signedJWT.serialize();

        // Prepare CredentialProof object
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setJwt(jwt);

        // Validate JWT
        boolean result = jwtProofValidator.validate("clientId", "someNonce", credentialProof);

        assertFalse(result, "No algorithm found exception");
    }

    @Test
    void testValidate_Es256WithNullHeaderType_InvalidAlgException() throws ParseException, JOSEException {
        // Generate a valid ECKey with ES256
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();

        // Create a public JWK from the private JWK
        JWK publicJwk = ecJWK.toPublicJWK();

        // Create JWS Header with public JWK
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .jwk(publicJwk)
                .type(null)
                .build();

        // Build JWT Claims
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("test-credential-id")
                .issuer("clientId")
                .claim("nonce", "someNonce")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 3600000)) // 1 hour from now
                .build();

        // Create and sign the JWT with the private EC key
        SignedJWT signedJWT = new SignedJWT(header, claims);
        JWSSigner signer = new ECDSASigner(ecJWK);
        signedJWT.sign(signer);

        // Serialize JWT
        String jwt = signedJWT.serialize();

        // Prepare CredentialProof object
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setJwt(jwt);

        // Validate JWT
        boolean result = jwtProofValidator.validate("clientId", "someNonce", credentialProof);

        assertFalse(result, "No algorithm found exception");
    }

    @Test
    void testValidate_Es256WithInvalidKeyId_InvalidAlgException() throws ParseException, JOSEException {
        ReflectionTestUtils.setField(jwtProofValidator, "supportedAlgorithms", List.of("RS256", "ES256", "Ed25519"));
        // Generate a valid ECKey with ES256
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();

        // Create JWS Header with public JWK
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .jwk(null)
                .keyID(null)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .build();

        // Build JWT Claims
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("test-credential-id")
                .issuer("clientId")
                .claim("nonce", "someNonce")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 3600000)) // 1 hour from now
                .build();

        // Create and sign the JWT with the private EC key
        SignedJWT signedJWT = new SignedJWT(header, claims);
        JWSSigner signer = new ECDSASigner(ecJWK);
        signedJWT.sign(signer);

        // Serialize JWT
        String jwt = signedJWT.serialize();

        // Prepare CredentialProof object
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setJwt(jwt);

        // Validate JWT
        boolean result = jwtProofValidator.validate("clientId", "someNonce", credentialProof);

        assertFalse(result, "No algorithm found exception");
    }

    @Test
    void testValidate_Es256WithNonNullHeaderJwkAndKeyId_InvalidAlgException() throws ParseException, JOSEException {
        ReflectionTestUtils.setField(jwtProofValidator, "supportedAlgorithms", List.of("RS256", "ES256", "Ed25519"));
        // Generate a valid ECKey with ES256
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();

        // Create a public JWK from the private JWK
        JWK publicJwk = ecJWK.toPublicJWK();

        // Create JWS Header with public JWK
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .jwk(publicJwk)
                .keyID(UUID.randomUUID().toString())
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .build();

        // Build JWT Claims
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("test-credential-id")
                .issuer("clientId")
                .claim("nonce", "someNonce")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 3600000)) // 1 hour from now
                .build();

        // Create and sign the JWT with the private EC key
        SignedJWT signedJWT = new SignedJWT(header, claims);
        JWSSigner signer = new ECDSASigner(ecJWK);
        signedJWT.sign(signer);

        // Serialize JWT
        String jwt = signedJWT.serialize();

        // Prepare CredentialProof object
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setJwt(jwt);

        // Validate JWT
        boolean result = jwtProofValidator.validate("clientId", "someNonce", credentialProof);

        assertFalse(result, "No algorithm found exception");
    }

    @Test
    void testValidate_ValidEd25519JWT() throws Exception {
        String keyId = "did:jwk:";
        String jwt = createValidEd25519JWT(keyId);

        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setJwt(jwt);

        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof);

        assertTrue(result, "Ed25519 JWT should be valid");
    }

    private String createValidEd25519JWT(String keyId) throws Exception {
        // Generate Ed25519 key pair
        OctetKeyPair edJWK = new OctetKeyPairGenerator(Curve.Ed25519)
                .keyID(UUID.randomUUID().toString())  // Use unique key ID
                .generate();

        // Create JWT header with Ed25519 algorithm and JWK
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.Ed25519)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .keyID(keyId + Base64.getUrlEncoder().withoutPadding().encodeToString(edJWK.toPublicJWK().toJSONString().getBytes(StandardCharsets.UTF_8)))
                .build();

        // Create JWT claims
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("test-credential-id")
                .issuer("test-client")
                .claim("nonce", "test-nonce")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 60000))
                .build();

        // Sign JWT with Ed25519
        SignedJWT jwt = new SignedJWT(header, claims);
        JWSSigner signer = new Ed25519Signer(edJWK);
        jwt.sign(signer);

        return jwt.serialize();
    }

    @Test
    void testValidate_Ed25519JWT_IllegalArgumentException() throws Exception {
        String signedJwt = createValidEd25519JWT("did:jwk: ");

        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setJwt(signedJwt);

        boolean result = jwtProofValidator.validate("test-client", "test-nonce", credentialProof);

        assertFalse(result, "Invalid base64 encoded ID");
    }

    @Test
    void testValidateV2_NullJwt() {
        when(credentialProof.getJwt()).thenReturn(null);
        boolean result = jwtProofValidator.validateV2("client-id", "nonce", credentialProof, Map.of("jwt", Map.of("proof_signing_alg_values_supported", List.of("RS256"))));
        assertFalse(result, "Expected validation to fail for null JWT in validateV2");
    }

    @Test
    void testValidateV2_BlankJwt() {
        when(credentialProof.getJwt()).thenReturn("");
        boolean result = jwtProofValidator.validateV2("client-id", "nonce", credentialProof, Map.of("jwt", Map.of("proof_signing_alg_values_supported", List.of("RS256"))));
        assertFalse(result, "Expected validation to fail for blank JWT in validateV2");
    }

    @Test
    void testValidateV2_UnsupportedAlgorithm() throws Exception {
        String jwt = createValidJWT();
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setJwt(jwt);
        // proofConfiguration with unsupported algorithm
        Map<String, Object> proofConfig = Map.of("jwt", Map.of("proof_signing_alg_values_supported", List.of("ES384")));
        boolean result = jwtProofValidator.validateV2("test-client", "test-nonce", credentialProof, proofConfig);
        assertFalse(result, "Expected validation to fail for unsupported algorithm in validateV2");
    }

    @Test
    void testGetInstance_DidJwkKid() {
        JwtProofKeyManager manager = jwtProofValidator.getInstance("did:jwk:abc");
        assertNotNull(manager);
        assertTrue(manager instanceof DIDjwkProofManager);
    }

    @Test
    void testGetInstance_DidKeyKid() {
        JwtProofKeyManager manager = jwtProofValidator.getInstance("did:key:abc");
        assertNotNull(manager);
        assertTrue(manager instanceof DIDkeysProofManager);
    }

    @Test
    void testGetInstance_OtherKid() {
        JwtProofKeyManager manager = jwtProofValidator.getInstance("random:abc");
        assertNotNull(manager);
        assertTrue(manager instanceof DIDjwkProofManager);
    }

    @Test
    void testValidateV2_ValidJWT_RS256() throws Exception {
        String jwt = createValidJWT();
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setJwt(jwt);
        Map<String, Object> proofConfig = Map.of("jwt", Map.of("proof_signing_alg_values_supported", List.of("RS256")));
        boolean result = jwtProofValidator.validateV2("test-client", "test-nonce", credentialProof, proofConfig);
        assertTrue(result, "Expected validation to succeed for valid RS256 JWT");
    }

    @Test
    void testValidateV2_ValidJWT_Ed25519() throws Exception {
        String keyId = "did:jwk:";
        String jwt = createValidEd25519JWT(keyId);
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setJwt(jwt);
        Map<String, Object> proofConfig = Map.of("jwt", Map.of("proof_signing_alg_values_supported", List.of("Ed25519")));
        boolean result = jwtProofValidator.validateV2("test-client", "test-nonce", credentialProof, proofConfig);
        assertTrue(result, "Expected validation to succeed for valid Ed25519 JWT");
    }

    @Test
    void testValidateV2_InvalidJWT() {
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setJwt("invalid.jwt.token");
        Map<String, Object> proofConfig = Map.of("jwt", Map.of("proof_signing_alg_values_supported", List.of("RS256")));
        boolean result = jwtProofValidator.validateV2("test-client", "test-nonce", credentialProof, proofConfig);
        assertFalse(result, "Expected validation to fail for invalid JWT in validateV2");
    }

    @Test
    void testValidateV2_MissingJwtConfig() throws Exception {
        String jwt = createValidJWT();
        CredentialProof credentialProof = new CredentialProof();
        credentialProof.setJwt(jwt);
        boolean result = jwtProofValidator.validateV2("test-client", "test-nonce", credentialProof, Map.of());
        assertFalse(result, "Expected validation to fail for missing jwt config in validateV2");
    }
}
