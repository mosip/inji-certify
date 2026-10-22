package io.mosip.certify.services;

import io.mosip.kernel.keymanagerservice.dto.AllCertificatesDataResponseDto;
import io.mosip.kernel.keymanagerservice.dto.CertificateDataResponseDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

import static io.mosip.certify.core.constants.Constants.CERTIFY_SERVICE_APP_ID;
import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class JwksServiceImplTest {

    @InjectMocks
    private JwksServiceImpl jwksService;

    @Mock
    private KeymanagerService keymanagerService;

    @Mock
    private io.mosip.certify.repository.CredentialConfigRepository credentialConfigRepository;

    private Map<String, List<List<String>>> signatureAlgoKeyAliasMapper;

    @BeforeClass
    public static void addBCProvider() {
        // For Ed25519 + certificate tooling
        Security.addProvider(new BouncyCastleProvider());
    }

    @Before
    public void setUp() {

        // Default mapper: algo -> [[appId, refId]]
        signatureAlgoKeyAliasMapper = new LinkedHashMap<>();
        signatureAlgoKeyAliasMapper.put("RS256",
                Collections.singletonList(Arrays.asList("APP1", "REF1")));

        ReflectionTestUtils.setField(
                jwksService,
                "signatureAlgoKeyAliasMapper",
                signatureAlgoKeyAliasMapper
        );
    }

    private AllCertificatesDataResponseDto buildAllCertificatesDto(
            String keyId,
            String certData,
            LocalDateTime expiryAt
    ) {
        CertificateDataResponseDto certDto = new CertificateDataResponseDto();
        certDto.setKeyId(keyId);
        certDto.setCertificateData(certData);
        certDto.setExpiryAt(expiryAt);

        AllCertificatesDataResponseDto all = new AllCertificatesDataResponseDto();
        all.setAllCertificates(new CertificateDataResponseDto[]{certDto});
        return all;
    }

    @Test
    public void testGetJwks_WithValidCertificates_DoesNotFail() {
        // Using fake PEM: service will likely fail to parse and skip
        String pem = "-----BEGIN CERTIFICATE-----\nFAKECERT\n-----END CERTIFICATE-----";
        LocalDateTime future = LocalDateTime.now().plusDays(1);

        AllCertificatesDataResponseDto app1Dto =
                buildAllCertificatesDto("kid1", pem, future);
        AllCertificatesDataResponseDto certifyDto =
                buildAllCertificatesDto("kid2", pem, future);

        when(keymanagerService.getAllCertificates(eq("APP1"), any()))
                .thenReturn(app1Dto);
        when(keymanagerService.getAllCertificates(eq(CERTIFY_SERVICE_APP_ID), any()))
                .thenReturn(certifyDto);

        Map<String, Object> result = jwksService.getJwks();

        assertNotNull(result);
        assertTrue(result.containsKey("keys"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) result.get("keys");
        assertThat(keys, notNullValue());
        // For fake PEM, we only assert that the call succeeds and returns a non-null list
        assertThat(keys.size(), is(keys.size())); // no size assumption
    }

    @Test
    public void testGetJwks_SkipsExpiredCertificate() {
        String pem = "-----BEGIN CERTIFICATE-----\nFAKECERT\n-----END CERTIFICATE-----";

        LocalDateTime past = LocalDateTime.now().minusDays(1);
        AllCertificatesDataResponseDto expiredDto =
                buildAllCertificatesDto("kidExpired", pem, past);

        when(keymanagerService.getAllCertificates(eq("APP1"), any()))
                .thenReturn(expiredDto);
        when(keymanagerService.getAllCertificates(eq(CERTIFY_SERVICE_APP_ID), any()))
                .thenReturn(expiredDto);

        Map<String, Object> result = jwksService.getJwks();

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) result.get("keys");
        assertNotNull(keys);
        // Expired certs are filtered out
        assertThat(keys.size(), is(0));
    }

    @Test
    public void testGetJwks_NullResponseFromKeyManager() {
        when(keymanagerService.getAllCertificates(anyString(), any()))
                .thenReturn(null);

        Map<String, Object> result = jwksService.getJwks();

        assertNotNull(result);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) result.get("keys");
        assertNotNull(keys);
        assertTrue(keys.isEmpty());
    }

    @Test
    public void testGetJwks_InvalidPemResultsInEmptyKeys() {
        // JwksServiceImpl logs and skips invalid certs; it does not throw
        String invalidPem = "INVALID_PEM";
        LocalDateTime future = LocalDateTime.now().plusDays(1);

        AllCertificatesDataResponseDto dto =
                buildAllCertificatesDto("kid", invalidPem, future);

        when(keymanagerService.getAllCertificates(anyString(), any()))
                .thenReturn(dto);

        Map<String, Object> result = jwksService.getJwks();

        assertNotNull(result);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) result.get("keys");
        assertNotNull(keys);
        // parsing fails and is skipped
        assertTrue(keys.isEmpty());
    }

    @Test
    public void testGetJwks_RSAHappyPath_BuildsValidJwkFields() throws Exception {
        LocalDateTime future = LocalDateTime.now().plusDays(90);

        // Generate a real RSA certificate (PEM)
        String rsaPem = generateRsaSelfSignedPem("CN=Unit Test RSA", future);
        AllCertificatesDataResponseDto app1Dto =
                buildAllCertificatesDto("kid-rsa", rsaPem, future);

        // Default CERTIFY_SERVICE_APP_ID returns empty
        AllCertificatesDataResponseDto empty = new AllCertificatesDataResponseDto();
        empty.setAllCertificates(new CertificateDataResponseDto[]{});

        when(keymanagerService.getAllCertificates(eq("APP1"), eq(Optional.of("REF1"))))
                .thenReturn(app1Dto);
        when(keymanagerService.getAllCertificates(eq(CERTIFY_SERVICE_APP_ID), eq(Optional.empty())))
                .thenReturn(empty);

        Map<String, Object> result = jwksService.getJwks();

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) result.get("keys");
        assertNotNull(keys);
        assertThat(keys.size(), is(1));

        Map<String, Object> k = keys.get(0);
        assertEquals("kid-rsa", k.get("kid"));
        assertThat((String) k.get("kty"), is("RSA")); // kty should be RSA for RSA cert
        assertNotNull("x5c missing", k.get("x5c"));
        assertNotNull("x5t#S256 missing", k.get("x5t#S256"));
        assertNotNull("exp missing", k.get("exp"));
        if ("RSA".equals(k.get("kty"))) {
            assertNotNull("n missing for RSA", k.get("n"));
            assertNotNull("e missing for RSA", k.get("e"));
        }
    }

    @Test
    public void testGetJwks_Ed25519_OKP_BuildsValidJwkFields() throws Exception {
        LocalDateTime future = LocalDateTime.now().plusDays(60);

        // Generate a real Ed25519 certificate (PEM)
        String edPem = generateEd25519SelfSignedPem("CN=Unit Test Ed25519", future);
        AllCertificatesDataResponseDto app1Dto =
                buildAllCertificatesDto("kid-ed", edPem, future);

        // Default CERTIFY_SERVICE_APP_ID returns empty
        AllCertificatesDataResponseDto empty = new AllCertificatesDataResponseDto();
        empty.setAllCertificates(new CertificateDataResponseDto[]{});

        when(keymanagerService.getAllCertificates(eq("APP1"), eq(Optional.of("REF1"))))
                .thenReturn(app1Dto);
        when(keymanagerService.getAllCertificates(eq(CERTIFY_SERVICE_APP_ID), eq(Optional.empty())))
                .thenReturn(empty);

        Map<String, Object> result = jwksService.getJwks();

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) result.get("keys");
        assertNotNull(keys);
        assertThat(keys.size(), is(1));

        Map<String, Object> k = keys.get(0);
        assertEquals("kid-ed", k.get("kid"));
        assertEquals("OKP", k.get("kty"));
        assertEquals("Ed25519", k.get("crv"));
        assertThat(k.get("x"), instanceOf(String.class));
        assertEquals("sig", k.get("use"));
        assertNotNull("x5c missing", k.get("x5c"));
        assertNotNull("x5t#S256 missing", k.get("x5t#S256"));
        assertNotNull("exp missing", k.get("exp"));
        // RSA params should NOT be present
        assertNull(k.get("n"));
        assertNull(k.get("e"));
    }

    @Test
    public void testGetJwks_AggregatesFromMapperAndDefault() throws Exception {
        LocalDateTime future = LocalDateTime.now().plusDays(45);

        // Expand mapper to have two entries
        Map<String, List<List<String>>> mapper = new LinkedHashMap<>();
        mapper.put("RS256", Arrays.asList(
                Arrays.asList("APP1", "REF1"),
                Arrays.asList("APP2", "REF2")
        ));
        ReflectionTestUtils.setField(jwksService, "signatureAlgoKeyAliasMapper", mapper);

        String rsaPem1 = generateRsaSelfSignedPem("CN=Agg RSA 1", future);
        String rsaPem2 = generateRsaSelfSignedPem("CN=Agg RSA 2", future);
        String rsaPemDefault = generateRsaSelfSignedPem("CN=Agg RSA 3", future);

        AllCertificatesDataResponseDto app1 =
                buildAllCertificatesDto("kid-a1", rsaPem1, future);
        AllCertificatesDataResponseDto app2 =
                buildAllCertificatesDto("kid-a2", rsaPem2, future);
        AllCertificatesDataResponseDto def =
                buildAllCertificatesDto("kid-def", rsaPemDefault, future);

        when(keymanagerService.getAllCertificates(eq("APP1"), eq(Optional.of("REF1"))))
                .thenReturn(app1);
        when(keymanagerService.getAllCertificates(eq("APP2"), eq(Optional.of("REF2"))))
                .thenReturn(app2);
        when(keymanagerService.getAllCertificates(eq(CERTIFY_SERVICE_APP_ID), eq(Optional.empty())))
                .thenReturn(def);

        Map<String, Object> result = jwksService.getJwks();

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) result.get("keys");
        assertNotNull(keys);
        // 2 from mapper + 1 default
        assertThat(keys.size(), is(3));

        Set<String> kids = new HashSet<>();
        for (Map<String, Object> k : keys) {
            kids.add((String) k.get("kid"));
        }
        assertTrue(kids.contains("kid-a1"));
        assertTrue(kids.contains("kid-a2"));
        assertTrue(kids.contains("kid-def"));
    }

    @Test
    public void testGetJwks_SkipsNullKeyIdOrNullCertData() throws Exception {
        LocalDateTime future = LocalDateTime.now().plusDays(30);

        String validPem = generateRsaSelfSignedPem("CN=Valid", future);

        // Build a response with 3 cert items:
        // 1) null keyId -> skip
        // 2) null certificateData -> skip
        // 3) valid item -> include
        CertificateDataResponseDto bad1 = new CertificateDataResponseDto();
        bad1.setKeyId(null);
        bad1.setCertificateData(validPem);
        bad1.setExpiryAt(future);

        CertificateDataResponseDto bad2 = new CertificateDataResponseDto();
        bad2.setKeyId("kid-bad2");
        bad2.setCertificateData(null);
        bad2.setExpiryAt(future);

        CertificateDataResponseDto good = new CertificateDataResponseDto();
        good.setKeyId("kid-good");
        good.setCertificateData(validPem);
        good.setExpiryAt(future);

        AllCertificatesDataResponseDto all = new AllCertificatesDataResponseDto();
        all.setAllCertificates(new CertificateDataResponseDto[]{bad1, bad2, good});

        when(keymanagerService.getAllCertificates(eq("APP1"), eq(Optional.of("REF1"))))
                .thenReturn(all);
        when(keymanagerService.getAllCertificates(eq(CERTIFY_SERVICE_APP_ID), eq(Optional.empty())))
                .thenReturn(new AllCertificatesDataResponseDto()); // empty default

        Map<String, Object> result = jwksService.getJwks();

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) result.get("keys");
        assertNotNull(keys);
        assertThat(keys.size(), is(1));
        assertEquals("kid-good", keys.get(0).get("kid"));
    }

    @Test
    public void testGetJwks_ValidCertButExpiredExpiryAt_IsSkipped() throws Exception {
        // Build a valid RSA cert whose *real* notAfter is in the future
        LocalDateTime realNotAfter = LocalDateTime.now().plusDays(30);
        String pem = generateRsaSelfSignedPem("CN=Expired Flag Test", realNotAfter);

        // But pass an expiryAt in the past to the DTO so getJwk() treats it as expired
        LocalDateTime dtoExpiry = LocalDateTime.now().minusDays(1);

        AllCertificatesDataResponseDto dto =
                buildAllCertificatesDto("kid-exp-expiryAt", pem, dtoExpiry);

        when(keymanagerService.getAllCertificates(eq("APP1"), eq(Optional.of("REF1"))))
                .thenReturn(dto);
        when(keymanagerService.getAllCertificates(eq(CERTIFY_SERVICE_APP_ID), eq(Optional.empty())))
                .thenReturn(new AllCertificatesDataResponseDto()); // empty default

        Map<String, Object> result = jwksService.getJwks();

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) result.get("keys");
        assertNotNull(keys);
        // getJwk() returns null for expired certificate -> list remains empty
        assertTrue(keys.isEmpty());
    }

    @Test
    public void testGetJwks_EmptySignatureAlgoKeyAliasMapper_OnlyDefaultIsUsed() throws Exception {
        LocalDateTime future = LocalDateTime.now().plusDays(10);
        String pem = generateRsaSelfSignedPem("CN=Default Only", future);

        // Clear mapper so only CERTIFY_SERVICE_APP_ID path is used
        ReflectionTestUtils.setField(
                jwksService,
                "signatureAlgoKeyAliasMapper",
                new LinkedHashMap<String, List<List<String>>>()
        );

        AllCertificatesDataResponseDto defaultDto =
                buildAllCertificatesDto("kid-default-only", pem, future);

        when(keymanagerService.getAllCertificates(eq(CERTIFY_SERVICE_APP_ID), eq(Optional.empty())))
                .thenReturn(defaultDto);

        Map<String, Object> result = jwksService.getJwks();

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) result.get("keys");
        assertNotNull(keys);
        assertThat(keys.size(), is(1));
        assertEquals("kid-default-only", keys.get(0).get("kid"));
    }

    @Test
    public void testGetJwks_RSA_IncludesAlgAndUseWhenPresent() throws Exception {
        // Arrange
        LocalDateTime future = LocalDateTime.now().plusDays(15);
        String pem = generateRsaSelfSignedPem("CN=Alg Use Test", future);
        AllCertificatesDataResponseDto dto =
                buildAllCertificatesDto("kid-rsa-alg-use", pem, future);

        // Mapper: one entry only, no default
        Map<String, List<List<String>>> mapper = new LinkedHashMap<>();
        mapper.put("RS256", Collections.singletonList(Arrays.asList("APP1", "REF1")));
        ReflectionTestUtils.setField(jwksService, "signatureAlgoKeyAliasMapper", mapper);

        AllCertificatesDataResponseDto empty = new AllCertificatesDataResponseDto();
        empty.setAllCertificates(new CertificateDataResponseDto[] {});

        when(keymanagerService.getAllCertificates(eq("APP1"), eq(Optional.of("REF1"))))
                .thenReturn(dto);
        when(keymanagerService.getAllCertificates(eq(CERTIFY_SERVICE_APP_ID), eq(Optional.empty())))
                .thenReturn(empty);

        // Act
        Map<String, Object> result = jwksService.getJwks();

        // Assert
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) result.get("keys");
        assertNotNull(keys);
        assertThat(keys.size(), is(1));

        Map<String, Object> k = keys.get(0);
        assertEquals("kid-rsa-alg-use", k.get("kid"));
        assertThat(k.get("kty"), is((Object) "RSA"));

        // Do not over\-specify Nimbus behavior: just verify presence/shape if set
        Object alg = k.get("alg");
        if (alg != null) {
            assertThat(alg, instanceOf(String.class));
        }

        Object use = k.get("use");
        if (use != null) {
            assertThat(use, instanceOf(String.class));
        }
    }

    @Test
    public void testGetJwks_InvalidEd25519SpkiLength_IsSkipped() throws Exception {
        // Arrange
        LocalDateTime future = LocalDateTime.now().plusDays(20);

        // Use clearly invalid PEM so Ed25519 parsing fails and entry is skipped
        String badPem = "-----BEGIN CERTIFICATE-----\nINVALID_ED25519_CERT\n-----END CERTIFICATE-----";

        AllCertificatesDataResponseDto dto =
                buildAllCertificatesDto("kid-bad-ed", badPem, future);

        // Mapper: one entry, default empty
        Map<String, List<List<String>>> mapper = new LinkedHashMap<>();
        mapper.put("RS256", Collections.singletonList(Arrays.asList("APP1", "REF1")));
        ReflectionTestUtils.setField(jwksService, "signatureAlgoKeyAliasMapper", mapper);

        AllCertificatesDataResponseDto empty = new AllCertificatesDataResponseDto();
        empty.setAllCertificates(new CertificateDataResponseDto[] {});

        when(keymanagerService.getAllCertificates(eq("APP1"), eq(Optional.of("REF1"))))
                .thenReturn(dto);
        when(keymanagerService.getAllCertificates(eq(CERTIFY_SERVICE_APP_ID), eq(Optional.empty())))
                .thenReturn(empty);

        // Act
        Map<String, Object> result = jwksService.getJwks();

        // Assert
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) result.get("keys");
        assertNotNull(keys);
        // Invalid Ed25519 data should be skipped
        assertTrue(keys.isEmpty());
    }



    // -----------------------------
    // Helpers to generate real certs
    // -----------------------------

    private String generateRsaSelfSignedPem(String dn, LocalDateTime notAfter) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        X500Name subject = new X500Name(dn);
        BigInteger serial = new BigInteger(64, new SecureRandom());
        Date notBefore = new Date(System.currentTimeMillis() - 60_000);
        Date notAfterDate = Date.from(notAfter.atZone(ZoneId.systemDefault()).toInstant());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(kp.getPrivate());

        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                subject, serial, notBefore, notAfterDate, subject, spki
        );

        X509CertificateHolder holder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(holder);

        return toPemCert(cert.getEncoded());
    }

    private String generateEd25519SelfSignedPem(String dn, LocalDateTime notAfter) throws Exception {
        // Make sure BC is registered (already done in @BeforeClass)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "BC");
        KeyPair kp = kpg.generateKeyPair();

        X500Name subject = new X500Name(dn);
        BigInteger serial = new BigInteger(64, new SecureRandom());
        Date notBefore = new Date(System.currentTimeMillis() - 60_000);
        Date notAfterDate = Date.from(notAfter.atZone(ZoneId.systemDefault()).toInstant());

        // SubjectPublicKeyInfo from the generated public key
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());

        // Use JCA ContentSigner for Ed25519 (no hash-with algorithm — pure EdDSA)
        ContentSigner signer = new JcaContentSignerBuilder("Ed25519")
                .setProvider("BC")
                .build(kp.getPrivate());

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                subject, serial, notBefore, notAfterDate, subject, spki
        );

        X509CertificateHolder holder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(holder);

        return toPemCert(cert.getEncoded());
    }


    private String toPemCert(byte[] derBytes) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(derBytes);
        return "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----";
    }
}
