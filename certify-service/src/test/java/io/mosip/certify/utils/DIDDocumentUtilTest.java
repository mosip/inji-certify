package io.mosip.certify.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.certify.core.exception.CertifyException;

class DIDDocumentUtilTest {


    @Test
    @SuppressWarnings("unchecked")
    void testGenerateDIDDocumentEd25519Signature2020() throws Exception {
        String vcSignAlgorithm = SignatureAlg.ED25519_SIGNATURE_SUITE_2020;
        String certificateString = "-----BEGIN CERTIFICATE-----\nMIIC2jCCAcKgAwIBAgIInbzaZeSXQqEwDQYJKoZIhvcNAQELBQAwgYsxCzAJBgNV\nBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQK\nDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxMjAwBgNVBAMMKXd3dy5l\neGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VEMjU1MTkpMB4XDTI0MTIyOTA4\nNDY1OFoXDTI3MTIyOTA4NDY1OFowgYYxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJL\nQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwO\nRVhBTVBMRS1DRU5URVIxLTArBgNVBAMMJENFUlRJRllfVkNfU0lHTl9FRDI1NTE5\nLUVEMjU1MTlfU0lHTjAqMAUGAytlcAMhAOX8AiOEEHfyJRKJsjshaJps736mS4zS\ncZVcdUpZpEbxoz8wPTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSVZaEpMbDVgrAy\nZP0ZlwMMXzhS9jAOBgNVHQ8BAf8EBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAAJ4\nPZb+6A5Q5Z2X18B3PLNLs5It2UTu+qL8PhQyoVpEoq44Efl+10qaAiBp7l66sYcf\nsYVhREnJaBACqsEy5cFTZ7j+7Q0GhuepnkYTS9n8DwlOgZgPU0tBBwthbixwFyME\ne2VdtuhyuVnGK8+W6VWMg+lQGyQwPgrzAf6L81bADn+cW6tIVoYd4uuNfoXeM0pL\nTtKMGEyRVdx3Q+wcLEGZXCTYPkUgf+mq8kqf9dCDdDgblPU891msZpg0KGRkLD28\nPF7FPhK0Hq4DzwfhdpiQMe7W19FyH/IXRprJi8LKx4V9Y/rBAvR2loLR0PwVl+VB\nB55c6EluZ6hn9xuwr9w=\n-----END CERTIFICATE-----\n";
        String issuerURI = "did:example:123";
        String issuerPublicKeyURI = "did:example:123#key-0";

        Map<String, Object> didDocument = DIDDocumentUtil.generateDIDDocument(vcSignAlgorithm, certificateString, issuerURI, issuerPublicKeyURI);
        assertEquals(didDocument.get("@context"), Collections.singletonList("https://www.w3.org/ns/did/v1"));
        assertEquals(issuerURI, didDocument.get("id"));
        assertEquals(Collections.singletonList(issuerPublicKeyURI), didDocument.get("authentication"));
        assertEquals(Collections.singletonList(issuerPublicKeyURI), didDocument.get("assertionMethod"));
       
        Map<String,String> verificationMethod = ((List<Map<String,String>>)didDocument.get("verificationMethod")).get(0);
        assertEquals(verificationMethod.get("publicKeyMultibase"), "z6Mkuw2HXTbK7fXoVbiuriHdm3NDDcVRYWxRymfzdTE6ZWgQ");
        assertEquals(verificationMethod.get("controller"), issuerURI);
        assertEquals(verificationMethod.get("id"), issuerPublicKeyURI);
        assertEquals(verificationMethod.get("type"), "Ed25519VerificationKey2020");
        assertEquals(verificationMethod.get("@context"), "https://w3id.org/security/suites/ed25519-2020/v1");
    }

    @Test
    @SuppressWarnings("unchecked")
    void testGenerateDIDDocumentEd25519Signature2018() throws Exception {
        String vcSignAlgorithm = SignatureAlg.ED25519_SIGNATURE_SUITE_2020;
        String certificateString = "-----BEGIN CERTIFICATE-----\nMIIC2jCCAcKgAwIBAgIInbzaZeSXQqEwDQYJKoZIhvcNAQELBQAwgYsxCzAJBgNV\nBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQK\nDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxMjAwBgNVBAMMKXd3dy5l\neGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VEMjU1MTkpMB4XDTI0MTIyOTA4\nNDY1OFoXDTI3MTIyOTA4NDY1OFowgYYxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJL\nQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwO\nRVhBTVBMRS1DRU5URVIxLTArBgNVBAMMJENFUlRJRllfVkNfU0lHTl9FRDI1NTE5\nLUVEMjU1MTlfU0lHTjAqMAUGAytlcAMhAOX8AiOEEHfyJRKJsjshaJps736mS4zS\ncZVcdUpZpEbxoz8wPTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSVZaEpMbDVgrAy\nZP0ZlwMMXzhS9jAOBgNVHQ8BAf8EBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAAJ4\nPZb+6A5Q5Z2X18B3PLNLs5It2UTu+qL8PhQyoVpEoq44Efl+10qaAiBp7l66sYcf\nsYVhREnJaBACqsEy5cFTZ7j+7Q0GhuepnkYTS9n8DwlOgZgPU0tBBwthbixwFyME\ne2VdtuhyuVnGK8+W6VWMg+lQGyQwPgrzAf6L81bADn+cW6tIVoYd4uuNfoXeM0pL\nTtKMGEyRVdx3Q+wcLEGZXCTYPkUgf+mq8kqf9dCDdDgblPU891msZpg0KGRkLD28\nPF7FPhK0Hq4DzwfhdpiQMe7W19FyH/IXRprJi8LKx4V9Y/rBAvR2loLR0PwVl+VB\nB55c6EluZ6hn9xuwr9w=\n-----END CERTIFICATE-----\n";
        String issuerURI = "did:example:123";
        String issuerPublicKeyURI = "did:example:123#key-0";

        Map<String, Object> didDocument = DIDDocumentUtil.generateDIDDocument(vcSignAlgorithm, certificateString, issuerURI, issuerPublicKeyURI);
        assertEquals(didDocument.get("@context"), Collections.singletonList("https://www.w3.org/ns/did/v1"));
        assertEquals(issuerURI, didDocument.get("id"));
        assertEquals(Collections.singletonList(issuerPublicKeyURI), didDocument.get("authentication"));
        assertEquals(Collections.singletonList(issuerPublicKeyURI), didDocument.get("assertionMethod"));
       
        Map<String,String> verificationMethod = ((List<Map<String,String>>)didDocument.get("verificationMethod")).get(0);
        assertEquals(verificationMethod.get("publicKeyMultibase"), "z6Mkuw2HXTbK7fXoVbiuriHdm3NDDcVRYWxRymfzdTE6ZWgQ");
        assertEquals(verificationMethod.get("controller"), issuerURI);
        assertEquals(verificationMethod.get("id"), issuerPublicKeyURI);
        assertEquals(verificationMethod.get("type"), "Ed25519VerificationKey2020");
        assertEquals(verificationMethod.get("@context"), "https://w3id.org/security/suites/ed25519-2020/v1");
    }

    @Test
    @SuppressWarnings("unchecked")
    void testGenerateDIDDocumentRSASignature2018() throws Exception {
        String vcSignAlgorithm = SignatureAlg.RSA_SIGNATURE_SUITE_2018;
        String certificateString = "-----BEGIN CERTIFICATE-----\nMIIDxzCCAq+gAwIBAgIIgusG+rdZJWgwDQYJKoZIhvcNAQELBQAweDELMAkGA1UE\nBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoM\nBUlJSVRCMRcwFQYDVQQLDA5FWEFNUExFLUNFTlRFUjEfMB0GA1UEAwwWd3d3LmV4\nYW1wbGUuY29tIChST09UKTAeFw0yNDEyMjkxMDQ4NDRaFw0yNzEyMjkxMDQ4NDRa\nMIGHMQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9S\nRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMS4wLAYD\nVQQDDCV3d3cuZXhhbXBsZS5jb20gKENFUlRJRllfVkNfU0lHTl9SU0EpMIIBIjAN\nBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlkO3CPWJ6Jqu9hzm4Eew7EJSbYCX\n7YGBxYAjRHcLuVgsttyRWUZ3DiRYEoN7bG/jCh7E0Gvv4M5ux4VSw3RJlM+9Tfje\nDUkHdZQ0g5A/r69uyy7+zE8MIM2fXcgwEgIZabm/Zb6+T/K6mSsdPQAHnBe1zXoq\ngTuyTT6pVsHbR0+5ULkhN3BuJyhJ7zw8vC1aiFYA2b05nU7H1Rn+axes8+v80mQS\nGR9iJTrGeYtvz8a+gRhvXmK+h8nhUAJaPHJBacCRMErKvgddWkWBtknJZQmnX0RN\n2IC5+egbE8thCVg8BGBcxOoUBHjHYmus0CZNbTMJQIObL62p7caJHnYtHwIDAQAB\no0UwQzASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBSOi5/6I4vvp8eshKNs\nSwr/BtWM/zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAKHiZu+1\nPjKqvlesbAj4QJkQlpdstz0PgEOnT6+flpcnmyMJj2QvWQbfX8niVWGMIc0HnO+H\ntzc/2oKmO9eQpmdnL4DN7NtuXxbTwTzsGDI934jRZGqHmeCh90j+T7QqSbk+GanC\nOMGFth7aV9j5cDSr7gCIom6N0TEUw/5a3O1+vJCwtQtN29H/+ksro+RYyN4/nbrR\ngix5XRR9VTcsLbM8J8dOxqZxsP+Bgebqp+fqv8QEea4cVYtStEMY6/4M6kKWyL7Q\nsmgwsJ5Vr5w/Y1hOIKaQe9WwWm/T8+byElVgZ/vT5tCYhLxHyBa1vfTgq1FQe5gb\nc6CDSimUO4tcosI=\n-----END CERTIFICATE-----\n";
        String issuerURI = "did:example:123";
        String issuerPublicKeyURI = "did:example:123#key-0";

        Map<String, Object> didDocument = DIDDocumentUtil.generateDIDDocument(vcSignAlgorithm, certificateString, issuerURI, issuerPublicKeyURI);
        assertEquals(didDocument.get("@context"), Collections.singletonList("https://www.w3.org/ns/did/v1"));
        assertEquals(issuerURI, didDocument.get("id"));
        assertEquals(Collections.singletonList(issuerPublicKeyURI), didDocument.get("authentication"));
        assertEquals(Collections.singletonList(issuerPublicKeyURI), didDocument.get("assertionMethod"));
       
        Map<String,Object> verificationMethod = ((List<Map<String,Object>>)didDocument.get("verificationMethod")).get(0);
        assertEquals(((Map<String,String>)verificationMethod.get("publicKeyJwk")).get("kty"), "RSA");
        assertEquals(((Map<String,String>)verificationMethod.get("publicKeyJwk")).get("e"), "AQAB");
        assertEquals(((Map<String,String>)verificationMethod.get("publicKeyJwk")).get("n"), "lkO3CPWJ6Jqu9hzm4Eew7EJSbYCX7YGBxYAjRHcLuVgsttyRWUZ3DiRYEoN7bG_jCh7E0Gvv4M5ux4VSw3RJlM-9TfjeDUkHdZQ0g5A_r69uyy7-zE8MIM2fXcgwEgIZabm_Zb6-T_K6mSsdPQAHnBe1zXoqgTuyTT6pVsHbR0-5ULkhN3BuJyhJ7zw8vC1aiFYA2b05nU7H1Rn-axes8-v80mQSGR9iJTrGeYtvz8a-gRhvXmK-h8nhUAJaPHJBacCRMErKvgddWkWBtknJZQmnX0RN2IC5-egbE8thCVg8BGBcxOoUBHjHYmus0CZNbTMJQIObL62p7caJHnYtHw");
        assertEquals(verificationMethod.get("controller"), issuerURI);
        assertEquals(verificationMethod.get("id"), issuerPublicKeyURI);
        assertEquals(verificationMethod.get("type"), "JsonWebKey2020");
        assertEquals(verificationMethod.get("@context"), "https://w3id.org/security/suites/jws-2020/v1");
    }

    @Test
    void testGenerateDIDDocumentUnsupportedAlgorithm() {
        String vcSignAlgorithm = "UnsupportedAlgorithm";
        String certificateString = "-----BEGIN CERTIFICATE-----\nMIIC2jCCAcKgAwIBAgIInbzaZeSXQqEwDQYJKoZIhvcNAQELBQAwgYsxCzAJBgNV\nBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQK\nDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxMjAwBgNVBAMMKXd3dy5l\neGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VEMjU1MTkpMB4XDTI0MTIyOTA4\nNDY1OFoXDTI3MTIyOTA4NDY1OFowgYYxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJL\nQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwO\nRVhBTVBMRS1DRU5URVIxLTArBgNVBAMMJENFUlRJRllfVkNfU0lHTl9FRDI1NTE5\nLUVEMjU1MTlfU0lHTjAqMAUGAytlcAMhAOX8AiOEEHfyJRKJsjshaJps736mS4zS\ncZVcdUpZpEbxoz8wPTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSVZaEpMbDVgrAy\nZP0ZlwMMXzhS9jAOBgNVHQ8BAf8EBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAAJ4\nPZb+6A5Q5Z2X18B3PLNLs5It2UTu+qL8PhQyoVpEoq44Efl+10qaAiBp7l66sYcf\nsYVhREnJaBACqsEy5cFTZ7j+7Q0GhuepnkYTS9n8DwlOgZgPU0tBBwthbixwFyME\ne2VdtuhyuVnGK8+W6VWMg+lQGyQwPgrzAf6L81bADn+cW6tIVoYd4uuNfoXeM0pL\nTtKMGEyRVdx3Q+wcLEGZXCTYPkUgf+mq8kqf9dCDdDgblPU891msZpg0KGRkLD28\nPF7FPhK0Hq4DzwfhdpiQMe7W19FyH/IXRprJi8LKx4V9Y/rBAvR2loLR0PwVl+VB\nB55c6EluZ6hn9xuwr9w=\n-----END CERTIFICATE-----\n";
        String issuerURI = "did:example:123";
        String issuerPublicKeyURI = "did:example:123#key-0";

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            DIDDocumentUtil.generateDIDDocument(vcSignAlgorithm, certificateString, issuerURI, issuerPublicKeyURI);
        });

        assertEquals("unsupported_algorithm", exception.getErrorCode());
    }

    @Test
    void testGenerateDIDDocumentWithInvalidCertificateString() {
        String invalidCertificateString = "INVALID_CERTIFICATE";
        String vcSignAlgorithm = SignatureAlg.RSA_SIGNATURE_SUITE_2018;
        String issuerURI = "did:web:example.com";
        String issuerPublicKeyURI = "did:web:example.com#key-0";

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            DIDDocumentUtil.generateDIDDocument(vcSignAlgorithm, invalidCertificateString, issuerURI, issuerPublicKeyURI);
        });

        assertEquals("invalid_certificate", exception.getErrorCode());
    }

}
