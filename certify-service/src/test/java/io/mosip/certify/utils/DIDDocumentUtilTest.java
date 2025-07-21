package io.mosip.certify.utils;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.certify.core.dto.CertificateResponseDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.kernel.keymanagerservice.dto.AllCertificatesDataResponseDto;
import io.mosip.kernel.keymanagerservice.dto.CertificateDataResponseDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

class DIDDocumentUtilTest {

    @Mock
    KeymanagerService keymanagerService;

    @InjectMocks
    DIDDocumentUtil didDocumentUtil;

    @BeforeEach
    void setUp() {
        // Initialize mocks before each test
        MockitoAnnotations.openMocks(this);
    }

    @Test
    @SuppressWarnings("unchecked")
    void testGenerateVerificationMethodEd25519Signature2020ViaReflection() {
        String signatureCryptoSuite = SignatureAlg.ED25519_SIGNATURE_SUITE_2020;
        String certificateString = "-----BEGIN CERTIFICATE-----\nMIIC2jCCAcKgAwIBAgIInbzaZeSXQqEwDQYJKoZIhvcNAQELBQAwgYsxCzAJBgNV\nBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQK\nDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxMjAwBgNVBAMMKXd3dy5l\neGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VEMjU1MTkpMB4XDTI0MTIyOTA4\nNDY1OFoXDTI3MTIyOTA4NDY1OFowgYYxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJL\nQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwO\nRVhBTVBMRS1DRU5URVIxLTArBgNVBAMMJENFUlRJRllfVkNfU0lHTl9FRDI1NTE5\nLUVEMjU1MTlfU0lHTjAqMAUGAytlcAMhAOX8AiOEEHfyJRKJsjshaJps736mS4zS\ncZVcdUpZpEbxoz8wPTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSVZaEpMbDVgrAy\nZP0ZlwMMXzhS9jAOBgNVHQ8BAf8EBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAAJ4\nPZb+6A5Q5Z2X18B3PLNLs5It2UTu+qL8PhQyoVpEoq44Efl+10qaAiBp7l66sYcf\nsYVhREnJaBACqsEy5cFTZ7j+7Q0GhuepnkYTS9n8DwlOgZgPU0tBBwthbixwFyME\ne2VdtuhyuVnGK8+W6VWMg+lQGyQwPgrzAf6L81bADn+cW6tIVoYd4uuNfoXeM0pL\nTtKMGEyRVdx3Q+wcLEGZXCTYPkUgf+mq8kqf9dCDdDgblPU891msZpg0KGRkLD28\nPF7FPhK0Hq4DzwfhdpiQMe7W19FyH/IXRprJi8LKx4V9Y/rBAvR2loLR0PwVl+VB\nB55c6EluZ6hn9xuwr9w=\n-----END CERTIFICATE-----\n";
        String kid = "test-kid-ed25519";
        String didUrl = "did:example:123";
        String issuerPublicKeyURI = didUrl + "#" + kid;

        Map<String, Object> verificationMethod = (Map<String, Object>) ReflectionTestUtils.invokeMethod(
                didDocumentUtil, "generateVerificationMethod", signatureCryptoSuite, certificateString, didUrl, kid);

        assertEquals("z6Mkuw2HXTbK7fXoVbiuriHdm3NDDcVRYWxRymfzdTE6ZWgQ", verificationMethod.get("publicKeyMultibase"));
        assertEquals(didUrl, verificationMethod.get("controller"));
        assertEquals(issuerPublicKeyURI, verificationMethod.get("id"));
        assertEquals("Ed25519VerificationKey2020", verificationMethod.get("type"));
        assertEquals("https://w3id.org/security/suites/ed25519-2020/v1", verificationMethod.get("@context"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testGenerateVerificationMethodRSASignature2018ViaReflection() {
        String signatureCryptoSuite = SignatureAlg.RSA_SIGNATURE_SUITE_2018;
        String certificateString = "-----BEGIN CERTIFICATE-----\nMIIDxzCCAq+gAwIBAgIIgusG+rdZJWgwDQYJKoZIhvcNAQELBQAweDELMAkGA1UE\nBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoM\nBUlJSVRCMRcwFQYDVQQLDA5FWEFNUExFLUNFTlRFUjEfMB0GA1UEAwwWd3d3LmV4\nYW1wbGUuY29tIChST09UKTAeFw0yNDEyMjkxMDQ4NDRaFw0yNzEyMjkxMDQ4NDRa\nMIGHMQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9S\nRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMS4wLAYD\nVQQDDCV3d3cuZXhhbXBsZS5jb20gKENFUlRJRllfVkNfU0lHTl9SU0ApMIIBIjAN\nBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlkO3CPWJ6Jqu9hzm4Eew7EJSbYCX\n7YGBxYAjRHcLuVgsttyRWUZ3DiRYEoN7bG/jCh7E0Gvv4M5ux4VSw3RJlM+9Tfje\nDUkHdZQ0g5A/r69uyy7+zE8MIM2fXcgwEgIZabm/Zb6+T/K6mSsdPQAHnBe1zXoq\ngTuyTT6pVsHbR0+5ULkhN3BuJyhJ7zw8vC1aiFYA2b05nU7H1Rn+axes8+v80mQS\nGR9iJTrGeYtvz8a+gRhvXmK+h8nhUAJaPHJBacCRMErKvgddWkWBtknJZQmnX0RN\n2IC5+egbE8thCVg8BGBcxOoUBHjHYmus0CZNbTMJQIObL62p7caJHnYtHwIDAQAB\no0UwQzASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBSOi5/6I4vvp8eshKNs\nSwr/BtWM/zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAKHiZu+1\nPjKqvlesbAj4QJkQlpdstz0PgEOnT6+flpcnmyMJj2QvWQbfX8niVWGMIc0HnO+H\ntzc/2oKmO9eQpmdnL4DN7NtuXxbTwTzsGDI934jRZGqHmeCh90j+T7QqSbk+GanC\nOMGFth7aV9j5cDSr7gCIom6N0TEUw/5a3O1+vJCwtQtN29H/+ksro+RYyN4/nbrR\ngix5XRR9VTcsLbM8J8dOxqZxsP+Bgebqp+fqv8QEea4cVYtStEMY6/4M6kKWyL7Q\nsmgwsJ5Vr5w/Y1hOIKaQe9WwWm/T8+byElVgZ/vT5tCYhLxHyBa1vfTgq1FQe5gb\nc6CDSimUO4tcosI=\n-----END CERTIFICATE-----\n";
        String kid = "test-kid-rsa";
        String didUrl = "did:example:123";
        String issuerPublicKeyURI = didUrl + "#" + kid;

        Map<String, Object> verificationMethod = (Map<String, Object>) ReflectionTestUtils.invokeMethod(
                didDocumentUtil, "generateVerificationMethod", signatureCryptoSuite, certificateString, didUrl, kid);

        Map<String,String> publicKeyJwk = (Map<String,String>)verificationMethod.get("publicKeyJwk");
        assertNotNull(publicKeyJwk);
        assertEquals("RSA", publicKeyJwk.get("kty"));
        assertEquals("AQAB", publicKeyJwk.get("e"));
        assertEquals("lkO3CPWJ6Jqu9hzm4Eew7EJSbYCX7YGBxYAjRHcLuVgsttyRWUZ3DiRYEoN7bG_jCh7E0Gvv4M5ux4VSw3RJlM-9TfjeDUkHdZQ0g5A_r69uyy7-zE8MIM2fXcgwEgIZabm_Zb6-T_K6mSsdPQAHnBe1zXoqgTuyTT6pVsHbR0-5ULkhN3BuJyhJ7zw8vC1aiFYA2b05nU7H1Rn-axes8-v80mQSGR9iJTrGeYtvz8a-gRhvXmK-h8nhUAJaPHJBacCRMErKvgddWkWBtknJZQmnX0RN2IC5-egbE8thCVg8BGBcxOoUBHjHYmus0CZNbTMJQIObL62p7caJHnYtHw", publicKeyJwk.get("n"));

        assertEquals(didUrl, verificationMethod.get("controller"));
        assertEquals(issuerPublicKeyURI, verificationMethod.get("id"));
        assertEquals("JsonWebKey2020", verificationMethod.get("type"));
        assertEquals("https://w3id.org/security/suites/jws-2020/v1", verificationMethod.get("@context"));
    }
    @Test
    @SuppressWarnings("unchecked")
    void testGenerateVerificationMethodECK1Signature2019ViaReflection() {
        String signatureCryptoSuite = SignatureAlg.EC_SECP256K1_2019;
        String certificateString = "-----BEGIN CERTIFICATE-----\nMIIDDTCCAfWgAwIBAgIIborC968KpkYwDQYJKoZIhvcNAQELBQAweDELMAkGA1UE\nBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoM\nBUlJSVRCMRcwFQYDVQQLDA5FWEFNUExFLUNFTlRFUjEfMB0GA1UEAwwWd3d3LmV4\nYW1wbGUuY29tIChST09UKTAeFw0yNTAxMzAwMjI3MzBaFw0yODAxMzAwMjI3MzBa\nMIGbMQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9S\nRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMUIwQAYD\nVQQDDDl3d3cuZXhhbXBsZS5jb20gKENFUlRJRllfVkNfU0lHTl9FQ19LMS1FQ19T\nRUNQMjU2SzFfU0lHTikwVjAQBgcqhkjOPQIBBgUrgQQACgNCAARJNEyvwE3dOioZ\nhZATESbn6aPKJKqr2IazrTT7hQyJlsDAto8mGANVD8+U43h0ZEgGVesuvwuaMgj7\nLnVrRUDzo0UwQzASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBTT5j1MZSg4\nfONSPosQb8SmeZ/OdDAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEB\nALFGo9udwFWHLrPfQth186H2VuSJ2qNu9vJiNUAgwTAwfM6q2rgpJKywD5Hmqtz1\nioFhr19eXznjQh3m4J75OKQEagmzVPeQvFEtMYuRZAkrX0kLNYhn/5pP8JnQ/W+p\nx+hm+MW0Txn3sX7QWHaSsIMk/vuemQwpjkfoJEzKzqISYlivS6ICCREye93oP57n\n2ZUvm42aKYZ188S9LLmAaXI9vJjXs+oG2G+OGf5P94jDsSvBnIxcU55ztTFogKug\n/N0TUTsda2ljpwhkxDkXYOc1hQTDJD2FIm+pwxwNyv35TYtcUxZhKvgM5AYyQHdG\neRsEPaaCsiGXftuXmdLzMkU=\n-----END CERTIFICATE-----\n";
        String kid = "test-kid-eck1";
        String didUrl = "did:example:123";
        String issuerPublicKeyURI = didUrl + "#" + kid;

        Map<String, Object> verificationMethod = (Map<String, Object>) ReflectionTestUtils.invokeMethod(
                didDocumentUtil, "generateVerificationMethod", signatureCryptoSuite, certificateString, didUrl, kid);

        Map<String,String> publicKeyJwk = (Map<String,String>)verificationMethod.get("publicKeyJwk");
        assertNotNull(publicKeyJwk);
        assertEquals("EC", publicKeyJwk.get("kty"));
        assertEquals("secp256k1", publicKeyJwk.get("crv"));
        assertEquals("STRMr8BN3ToqGYWQExEm5-mjyiSqq9iGs600-4UMiZY", publicKeyJwk.get("x"));
        assertEquals("wMC2jyYYA1UPz5TjeHRkSAZV6y6_C5oyCPsudWtFQPM", publicKeyJwk.get("y"));

        assertEquals(didUrl, verificationMethod.get("controller"));
        assertEquals(issuerPublicKeyURI, verificationMethod.get("id"));
        assertEquals("EcdsaSecp256k1VerificationKey2019", verificationMethod.get("type"));
        assertEquals("https://w3id.org/security/v1", verificationMethod.get("@context"));
    }
    @Test
    @SuppressWarnings("unchecked")
    void testGenerateVerificationMethodECR1Signature2019ViaReflection() {
        String signatureCryptoSuite = SignatureAlg.EC_SECP256R1_2019;
        String certificateString = "-----BEGIN CERTIFICATE-----\nMIIDEDCCAfigAwIBAgIIZ1nHaUeKLDMwDQYJKoZIhvcNAQELBQAweDELMAkGA1UE\nBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoM\nBUlJSVRCMRcwFQYDVQQLDA5FWEFNUExFLUNFTlRFUjEfMB0GA1UEAwwWd3d3LmV4\nYW1wbGUuY29tIChST09UKTAeFw0yNTA0MDcwMTQ1MzVaFw0yODA0MDYwMTQ1MzVa\nMIGbMQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9S\nRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMUIwQAYD\nVQQDDDl3d3cuZXhhbXBsZS5jb20gKENFUlRJRllfVkNfU0lHTl9FQ19SMS1FQ19T\nRUNQMjU2UjFfU0lHTikwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARnZrptfF7k\nyWism4kK6l8N6K4v8H3FyYzlkDc8/mP55pa+gTUvcEN4DF7jAZntyYUL8GE3Eupf\nd2ZdL7ojg2sgo0UwQzASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBRIWCn1\nRWbTDjYmBJLsnQ5jKyYudzAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQAD\nggEBAIM3Mv1W3N5htKcNEhvtkRYhl0MthNRNzNOuNSRu8VHBgverGE438vdbCQ2f\n/CGBI+Jo2IHdsaFOFGvb6TOOjEZFPgGJyPBK1PGqZc/OiqIcLvPwQ0HVQbp6fgHC\nxocizOAZmrjCQSgQgcDQSuO9tv9JV3Vb7odnPFlbtpREN23AS4KMyVYRm06CrSac\nPW44fSP4GSbWHmgaBvhWxJcXJ/4LpK+UQ1Q0dszm6ofgppd18oSwix90NRDTej7J\nAXmfM3eCvGvMlJC3jHs4EFns9egC16hHqX7INpE1K/ZNyTgHhXpErqaDWw2xkkPC\nvVFPORPyyNumlhL/f36CtutMe2U=\n-----END CERTIFICATE-----\n";
        String kid = "test-kid-ecr1";
        String didUrl = "did:example:123";
        String issuerPublicKeyURI = didUrl + "#" + kid;

        Map<String, Object> verificationMethod = (Map<String, Object>) ReflectionTestUtils.invokeMethod(
                didDocumentUtil, "generateVerificationMethod", signatureCryptoSuite, certificateString, didUrl, kid);

        assertEquals(didUrl, verificationMethod.get("controller"));
        assertEquals("zDnaeXPbtiMpLqxAH31Q9iJgsX7VKtf4z7GQPj5FEGJfBDBGR", verificationMethod.get("publicKeyMultibase"));
        assertEquals(issuerPublicKeyURI, verificationMethod.get("id"));
        assertEquals("EcdsaSecp256r1VerificationKey2019", verificationMethod.get("type"));
        assertEquals("https://w3id.org/security/suites/ecdsa-2019/v1", verificationMethod.get("@context"));
    }

    @Test
    void testGenerateVerificationMethodUnsupportedAlgorithmViaReflection() {
        String signatureCryptoSuite = "UnsupportedAlgorithm";
        String certificateString = "-----BEGIN CERTIFICATE-----\nMIIC2jCCAcKgAwIBAgIInbzaZeSXQqEwDQYJKoZIhvcNAQELBQAwgYsxCzAJBgNV\nBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQK\nDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxMjAwBgNVBAMMKXd3dy5l\neGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VEMjU1MTkpMB4XDTI0MTIyOTA4\nNDY1OFoXDTI3MTIyOTA4NDY1OFowgYYxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJL\nQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwO\nRVhBTVBMRS1DRU5URVIxLTArBgNVBAMMJENFUlRJRllfVkNfU0lHTl9FRDI1NTE5\nLUVEMjU1MTlfU0lHTjAqMAUGAytlcAMhAOX8AiOEEHfyJRKJsjshaJps736mS4zS\ncZVcdUpZpEbxoz8wPTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSVZaEpMbDVgrAy\nZP0ZlwMMXzhS9jAOBgNVHQ8BAf8EBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAAJ4\nPZb+6A5Q5Z2X18B3PLNLs5It2UTu+qL8PhQyoVpEoq44Efl+10qaAiBp7l66sYcf\nsYVhREnJaBACqsEy5cFTZ7j+7Q0GhuepnkYTS9n8DwlOgZgPU0tBBwthbixwFyME\ne2VdtuhyuVnGK8+W6VWMg+lQGyQwPgrzAf6L81bADn+cW6tIVoYd4uuNfoXeM0pL\nTtKMGEyRVdx3Q+wcLEGZXCTYPkUgf+mq8kqf9dCDdDgblPU891msZpg0KGRkLD28\nPF7FPhK0Hq4DzwfhdpiQMe7W19FyH/IXRprJi8LKx4V9Y/rBAvR2loLR0PwVl+VB\nB55c6EluZ6hn9xuwr9w=\n-----END CERTIFICATE-----\n";
        String kid = "test-kid";
        String didUrl = "did:example:123";

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            ReflectionTestUtils.invokeMethod(didDocumentUtil, "generateVerificationMethod", signatureCryptoSuite, certificateString, didUrl, kid);
        });

        assertEquals(ErrorConstants.UNSUPPORTED_ALGORITHM, exception.getErrorCode());
    }

    @Test
    void testGenerateVerificationMethodWithInvalidCertificateStringViaReflection() {
        String invalidCertificateString = "INVALID_CERTIFICATE";
        String signatureCryptoSuite = SignatureAlg.RSA_SIGNATURE_SUITE_2018;
        String kid = "test-kid";
        String didUrl = "did:example:123";

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            ReflectionTestUtils.invokeMethod(didDocumentUtil, "generateVerificationMethod", signatureCryptoSuite, invalidCertificateString, didUrl, kid);
        });

        assertEquals(ErrorConstants.INVALID_CERTIFICATE, exception.getErrorCode());
    }

    @Test
    void testGenerateDIDDocumentSuccess() {
        String didUrl = "did:example:123";

        // Setup mock responses for keymanagerService for each algorithm defined in CertifyIssuanceServiceImpl.keyChooser
        // This simulates the certificate data that generateDIDDocument will fetch.

        // ED25519 (for SignatureAlg.ED25519_SIGNATURE_SUITE_2018 and ED25519_SIGNATURE_SUITE_2020)
        CertificateDataResponseDto ed25519CertDto = new CertificateDataResponseDto();
        ed25519CertDto.setCertificateData("-----BEGIN CERTIFICATE-----\nMIIC2jCCAcKgAwIBAgIInbzaZeSXQqEwDQYJKoZIhvcNAQELBQAwgYsxCzAJBgNV\nBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQK\nDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxMjAwBgNVBAMMKXd3dy5l\neGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VEMjU1MTkpMB4XDTI0MTIyOTA4\nNDY1OFoXDTI3MTIyOTA4NDY1OFowgYYxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJL\nQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwO\nRVhBTVBMRS1DRU5URVIxLTArBgNVBAMMJENFUlRJRllfVkNfU0lHTl9FRDI1NTE5\nLUVEMjU1MTlfU0lHTjAqMAUGAytlcAMhAOX8AiOEEHfyJRKJsjshaJps736mS4zS\ncZVcdUpZpEbxoz8wPTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSVZaEpMbDVgrAy\nZP0ZlwMMXzhS9jAOBgNVHQ8BAf8EBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAAJ4\nPZb+6A5Q5Z2X18B3PLNLs5It2UTu+qL8PhQyoVpEoq44Efl+10qaAiBp7l66sYcf\nsYVhREnJaBACqsEy5cFTZ7j+7Q0GhuepnkYTS9n8DwlOgZgPU0tBBwthbixwFyME\ne2VdtuhyuVnGK8+W6VWMg+lQGyQwPgrzAf6L81bADn+cW6tIVoYd4uuNfoXeM0pL\nTtKMGEyRVdx3Q+wcLEGZXCTYPkUgf+mq8kqf9dCDdDgblPU891msZpg0KGRkLD28\nPF7FPhK0Hq4DzwfhdpiQMe7W19FyH/IXRprJi8LKx4V9Y/rBAvR2loLR0PwVl+VB\nB55c6EluZ6hn9xuwr9w=\n-----END CERTIFICATE-----\n");
        ed25519CertDto.setKeyId("ED25519_REF_ID");
        ed25519CertDto.setExpiryAt(LocalDateTime.now().plusYears(1)); // Set expiry in future
        when(keymanagerService.getAllCertificates(eq("CERTIFY_VC_SIGN_ED25519"), any(Optional.class)))
                .thenReturn(new AllCertificatesDataResponseDto(new CertificateDataResponseDto[]{ed25519CertDto}));

        // RSA (for SignatureAlg.RSA_SIGNATURE_SUITE_2018)
        CertificateDataResponseDto rsaCertDto = new CertificateDataResponseDto();
        rsaCertDto.setCertificateData("-----BEGIN CERTIFICATE-----\nMIIDxzCCAq+gAwIBAgIIgusG+rdZJWgwDQYJKoZIhvcNAQELBQAweDELMAkGA1UE\nBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoM\nBUlJSVRCMRcwFQYDVQQLDA5FWEFNUExFLUNFTlRFUjEfMB0GA1UEAwwWd3d3LmV4\nYW1wbGUuY29tIChST09UKTAeFw0yNDEyMjkxMDQ4NDRaFw0yNzEyMjkxMDQ4NDRa\nMIGHMQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9S\nRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMS4wLAYD\nVQQDDCV3d3cuZXhhbXBsZS5jb20gKENFUlRJRllfVkNfU0lHTl9SU0ApMIIBIjAN\nBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlkO3CPWJ6Jqu9hzm4Eew7EJSbYCX\n7YGBxYAjRHcLuVgsttyRWUZ3DiRYEoN7bG/jCh7E0Gvv4M5ux4VSw3RJlM+9Tfje\nDUkHdZQ0g5A/r69uyy7+zE8MIM2fXcgwEgIZabm/Zb6+T/K6mSsdPQAHnBe1zXoq\ngTuyTT6pVsHbR0+5ULkhN3BuJyhJ7zw8vC1aiFYA2b05nU7H1Rn+axes8+v80mQS\nGR9iJTrGeYtvz8a+gRhvXmK+h8nhUAJaPHJBacCRMErKvgddWkWBtknJZQmnX0RN\n2IC5+egbE8thCVg8BGBcxOoUBHjHYmus0CZNbTMJQIObL62p7caJHnYtHwIDAQAB\no0UwQzASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBSOi5/6I4vvp8eshKNs\nSwr/BtWM/zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAKHiZu+1\nPjKqvlesbAj4QJkQlpdstz0PgEOnT6+flpcnmyMJj2QvWQbfX8niVWGMIc0HnO+H\ntzc/2oKmO9eQpmdnL4DN7NtuXxbTwTzsGDI934jRZGqHmeCh90j+T7QqSbk+GanC\nOMGFth7aV9j5cDSr7gCIom6N0TEUw/5a3O1+vJCwtQtN29H/+ksro+RYyN4/nbrR\ngix5XRR9VTcsLbM8J8dOxqZxsP+Bgebqp+fqv8QEea4cVYtStEMY6/4M6kKWyL7Q\nsmgwsJ5Vr5w/Y1hOIKaQe9WwWm/T8+byElVgZ/vT5tCYhLxHyBa1vfTgq1FQe5gb\nc6CDSimUO4tcosI=\n-----END CERTIFICATE-----\n");
        rsaCertDto.setKeyId("EMPTY_REF_ID");
        rsaCertDto.setExpiryAt(LocalDateTime.now().plusYears(1)); // Set expiry in future
        when(keymanagerService.getAllCertificates(eq("CERTIFY_VC_SIGN_RSA"), any(Optional.class)))
                .thenReturn(new AllCertificatesDataResponseDto(new CertificateDataResponseDto[]{rsaCertDto}));

        // EC_SECP256K1_2019 (for SignatureAlg.EC_K1_2016 and EC_SECP256K1_2019)
        CertificateDataResponseDto ecK1CertDto = new CertificateDataResponseDto();
        ecK1CertDto.setCertificateData("-----BEGIN CERTIFICATE-----\nMIIDDTCCAfWgAwIBAgIIborC968KpkYwDQYJKoZIhvcNAQELBQAweDELMAkGA1UE\nBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoM\nBUlJSVRCMRcwFQYDVQQLDA5FWEFNUExFLUNFTlRFUjEfMB0GA1UEAwwWd3d3LmV4\nYW1wbGUuY29tIChST09UKTAeFw0yNTAxMzAwMjI3MzBaFw0yODAxMzAwMjI3MzBa\nMIGbMQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9S\nRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMUIwQAYD\nVQQDDDl3d3cuZXhhbXBsZS5jb20gKENFUlRJRllfVkNfU0lHTl9FQ19LMS1FQ19T\nRUNQMjU2SzFfU0lHTikwVjAQBgcqhkjOPQIBBgUrgQQACgNCAARJNEyvwE3dOioZ\nhZATESbn6aPKJKqr2IazrTT7hQyJlsDAto8mGANVD8+U43h0ZEgGVesuvwuaMgj7\nLnVrRUDzo0UwQzASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBTT5j1MZSg4\nfONSPosQb8SmeZ/OdDAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEB\nALFGo9udwFWHLrPfQth186H2VuSJ2qNu9vJiNUAgwTAwfM6q2rgpJKywD5Hmqtz1\nioFhr19eXznjQh3m4J75OKQEagmzVPeQvFEtMYuRZAkrX0kLNYhn/5pP8JnQ/W+p\nx+hm+MW0Txn3sX7QWHaSsIMk/vuemQwpjkfoJEzKzqISYlivS6ICCREye93oP57n\n2ZUvm42aKYZ188S9LLmAaXI9vJjXs+oG2G+OGf5P94jDsSvBnIxcU55ztTFogKug\n/N0TUTsda2ljpwhkxDkXYOc1hQTDJD2FIm+pwxwNyv35TYtcUxZhKvgM5AYyQHdG\neRsEPaaCsiGXftuXmdLzMkU=\n-----END CERTIFICATE-----\n");
        ecK1CertDto.setKeyId("EC_SECP256K1_SIGN");
        ecK1CertDto.setExpiryAt(LocalDateTime.now().plusYears(1)); // Set expiry in future
        when(keymanagerService.getAllCertificates(eq("CERTIFY_VC_SIGN_EC_K1"), any(Optional.class)))
                .thenReturn(new AllCertificatesDataResponseDto(new CertificateDataResponseDto[]{ecK1CertDto}));

        // EC_SECP256R1_2019 (for SignatureAlg.EC_SECP256R1_2019)
        CertificateDataResponseDto ecR1CertDto = new CertificateDataResponseDto();
        ecR1CertDto.setCertificateData("-----BEGIN CERTIFICATE-----\nMIIDEDCCAfigAwIBAgIIZ1nHaUeKLDMwDQYJKoZIhvcNAQELBQAweDELMAkGA1UE\nBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoM\nBUlJSVRCMRcwFQYDVQQLDA5FWEFNUExFLUNFTlRFUjEfMB0GA1UEAwwWd3d3LmV4\nYW1wbGUuY29tIChST09UKTAeFw0yNTA0MDcwMTQ1MzVaFw0yODA0MDYwMTQ1MzVa\nMIGbMQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9S\nRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMUIwQAYD\nVQQDDDl3d3cuZXhhbXBsZS5jb20gKENFUlRJRllfVkNfU0lHTl9FQ19SMS1FQ19T\nRUNQMjU2UjFfU0lHTikwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARnZrptfF7k\nyWism4kK6l8N6K4v8H3FyYzlkDc8/mP55pa+gTUvcEN4DF7jAZntyYUL8GE3Eupf\nd2ZdL7ojg2sgo0UwQzASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBRIWCn1\nRWbTDjYmBJLsnQ5jKyYudzAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQAD\nggEBAIM3Mv1W3N5htKcNEhvtkRYhl0MthNRNzNOuNSRu8VHBgverGE438vdbCQ2f\n/CGBI+Jo2IHdsaFOFGvb6TOOjEZFPgGJyPBK1PGqZc/OiqIcLvPwQ0HVQbp6fgHC\nxocizOAZmrjCQSgQgcDQSuO9tv9JV3Vb7odnPFlbtpREN23AS4KMyVYRm06CrSac\nPW44fSP4GSbWHmgaBvhWxJcXJ/4LpK+UQ1Q0dszm6ofgppd18oSwix90NRDTej7J\nAXmfM3eCvGvMlJC3jHs4EFns9egC16hHqX7INpE1K/ZNyTgHhXpErqaDWw2xkkPC\nvVFPORPyyNumlhL/f36CtutMe2U=\n-----END CERTIFICATE-----\n");
        ecR1CertDto.setKeyId("EC_SECP256R1_SIGN");
        ecR1CertDto.setExpiryAt(LocalDateTime.now().plusYears(1)); // Set expiry in future
        when(keymanagerService.getAllCertificates(eq("CERTIFY_VC_SIGN_EC_R1"), any(Optional.class)))
                .thenReturn(new AllCertificatesDataResponseDto(new CertificateDataResponseDto[]{ecR1CertDto}));


        Map<String, Object> didDocument = didDocumentUtil.generateDIDDocument(didUrl);

        assertNotNull(didDocument);
        assertEquals(didUrl, didDocument.get("id"));
        assertEquals(Collections.singletonList("https://www.w3.org/ns/did/v1"), didDocument.get("@context"));
        assertTrue(((List<?>) didDocument.get("alsoKnownAs")).isEmpty());
        assertTrue(((List<?>) didDocument.get("service")).isEmpty());
        assertEquals(Collections.singletonList(didUrl), didDocument.get("authentication"));
        assertEquals(Collections.singletonList(didUrl), didDocument.get("assertionMethod"));

        List<Map<String, Object>> verificationMethods = (List<Map<String, Object>>) didDocument.get("verificationMethod");
        assertNotNull(verificationMethods);
        assertEquals(4, verificationMethods.size()); // Expecting 4 unique verification methods based on keyChooser

        // Create a mutable copy of the list before sorting
        List<Map<String, Object>> mutableVerificationMethods = new ArrayList<>(verificationMethods);
        // Sort by 'id' to ensure consistent order for assertions
        mutableVerificationMethods.sort(Comparator.comparing(vm -> vm.get("id").toString()));

        // Verify specific properties of each generated verification method
        // EC_SECP256K1_SIGN
        Map<String, Object> ecK1Vm = mutableVerificationMethods.get(0);
        assertEquals(didUrl + "#EC_SECP256K1_SIGN", ecK1Vm.get("id"));
        assertEquals("EcdsaSecp256k1VerificationKey2019", ecK1Vm.get("type"));
        Map<String,String> ecK1Jwk = (Map<String,String>)ecK1Vm.get("publicKeyJwk");
        assertNotNull(ecK1Jwk);
        assertEquals("EC", ecK1Jwk.get("kty"));
        assertEquals("secp256k1", ecK1Jwk.get("crv"));
        assertEquals("STRMr8BN3ToqGYWQExEm5-mjyiSqq9iGs600-4UMiZY", ecK1Jwk.get("x"));
        assertEquals("wMC2jyYYA1UPz5TjeHRkSAZV6y6_C5oyCPsudWtFQPM", ecK1Jwk.get("y"));
        assertEquals(didUrl, ecK1Vm.get("controller"));
        assertEquals("https://w3id.org/security/v1", ecK1Vm.get("@context"));

        // EC_SECP256R1_SIGN
        Map<String, Object> ecR1Vm = mutableVerificationMethods.get(1);
        assertEquals(didUrl + "#EC_SECP256R1_SIGN", ecR1Vm.get("id"));
        assertEquals("EcdsaSecp256r1VerificationKey2019", ecR1Vm.get("type"));
        assertEquals("zDnaeXPbtiMpLqxAH31Q9iJgsX7VKtf4z7GQPj5FEGJfBDBGR", ecR1Vm.get("publicKeyMultibase"));
        assertEquals(didUrl, ecR1Vm.get("controller"));
        assertEquals("https://w3id.org/security/suites/ecdsa-2019/v1", ecR1Vm.get("@context"));

        // ED25519
        Map<String, Object> ed25519Vm = mutableVerificationMethods.get(2);
        assertEquals(didUrl + "#ED25519_REF_ID", ed25519Vm.get("id"));
        assertEquals("Ed25519VerificationKey2020", ed25519Vm.get("type"));
        assertEquals("z6Mkuw2HXTbK7fXoVbiuriHdm3NDDcVRYWxRymfzdTE6ZWgQ", ed25519Vm.get("publicKeyMultibase"));
        assertEquals(didUrl, ed25519Vm.get("controller"));
        assertEquals("https://w3id.org/security/suites/ed25519-2020/v1", ed25519Vm.get("@context"));

        // RSA
        Map<String, Object> rsaVm = mutableVerificationMethods.get(3);
        assertEquals(didUrl + "#EMPTY_REF_ID", rsaVm.get("id"));
        assertEquals("JsonWebKey2020", rsaVm.get("type"));
        Map<String,String> rsaJwk = (Map<String,String>)rsaVm.get("publicKeyJwk");
        assertNotNull(rsaJwk);
        assertEquals("RSA", rsaJwk.get("kty"));
        assertEquals("AQAB", rsaJwk.get("e"));
        assertEquals("lkO3CPWJ6Jqu9hzm4Eew7EJSbYCX7YGBxYAjRHcLuVgsttyRWUZ3DiRYEoN7bG_jCh7E0Gvv4M5ux4VSw3RJlM-9TfjeDUkHdZQ0g5A_r69uyy7-zE8MIM2fXcgwEgIZabm_Zb6-T_K6mSsdPQAHnBe1zXoqgTuyTT6pVsHbR0-5ULkhN3BuJyhJ7zw8vC1aiFYA2b05nU7H1Rn-axes8-v80mQSGR9iJTrGeYtvz8a-gRhvXmK-h8nhUAJaPHJBacCRMErKvgddWkWBtknJZQmnX0RN2IC5-egbE8thCVg8BGBcxOoUBHjHYmus0CZNbTMJQIObL62p7caJHnYtHw", rsaJwk.get("n"));
        assertEquals(didUrl, rsaVm.get("controller"));
        assertEquals("https://w3id.org/security/suites/jws-2020/v1", rsaVm.get("@context"));
    }

    @Test
    void testGenerateDIDDocumentWhenKeymanagerServiceReturnsNoCertificates() {
        String didUrl = "did:example:123";

        // Mock keymanagerService to return null certificates
        when(keymanagerService.getAllCertificates(any(String.class), any(Optional.class)))
                .thenReturn(new AllCertificatesDataResponseDto(null));

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            didDocumentUtil.generateDIDDocument(didUrl);
        });

        assertEquals("No certificates found", exception.getMessage());
    }

    @Test
    void testGetCertificateDataResponseDtoSuccess() {
        String appId = "test-app";
        String refId = "test-ref";
        CertificateDataResponseDto expectedDto = new CertificateDataResponseDto();
        expectedDto.setCertificateData("mock-certificate-data");
        expectedDto.setExpiryAt(LocalDateTime.now().plusYears(1));
        expectedDto.setKeyId("mock-key-id");

        AllCertificatesDataResponseDto mockResponse = new AllCertificatesDataResponseDto(
                new CertificateDataResponseDto[]{expectedDto});

        when(keymanagerService.getAllCertificates(appId, Optional.of(refId)))
                .thenReturn(mockResponse);

        CertificateResponseDTO result = didDocumentUtil.getCertificateDataResponseDto(appId, refId);

        assertNotNull(result);
        assertEquals(expectedDto.getCertificateData(), result.getCertificateData());
        assertEquals(expectedDto.getKeyId(), result.getKeyId());
    }

    @Test
    void testGetCertificateDataResponseDtoNoCertificatesFound() {
        String appId = "test-app";
        String refId = "test-ref";

        // Case 1: getAllCertificates returns null
        when(keymanagerService.getAllCertificates(appId, Optional.of(refId)))
                .thenReturn(new AllCertificatesDataResponseDto(null));

        CertifyException exception1 = assertThrows(CertifyException.class, () -> {
            didDocumentUtil.getCertificateDataResponseDto(appId, refId);
        });
        assertEquals("No certificates found", exception1.getMessage());

        // Case 2: getAllCertificates returns empty array
        when(keymanagerService.getAllCertificates(appId, Optional.of(refId)))
                .thenReturn(new AllCertificatesDataResponseDto(new CertificateDataResponseDto[]{}));

        CertifyException exception2 = assertThrows(CertifyException.class, () -> {
            didDocumentUtil.getCertificateDataResponseDto(appId, refId);
        });
        assertEquals("No certificates found", exception2.getMessage());
    }
}
