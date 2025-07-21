package io.mosip.certify.vcsigners;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import io.mosip.certify.core.dto.CertificateResponseDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.proofgenerators.ProofGeneratorFactory;
import io.mosip.certify.utils.DIDDocumentUtil;
import io.mosip.kernel.keymanagerservice.dto.CertificateDataResponseDto;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import static org.mockito.ArgumentMatchers.any;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import static org.mockito.Mockito.when;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.proofgenerators.ProofGenerator;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.service.SignatureService;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;

@RunWith(MockitoJUnitRunner.class)
public class JsonLDVCSignerTest {
    @Mock
    SignatureService signatureService;
    @Mock
    ProofGenerator signProps;
    @Mock
    ProofGeneratorFactory proofGeneratorFactory;
    @Mock
    DIDDocumentUtil didDocumentUtil;
    @InjectMocks
    private JsonLDVCSigner jsonLDVCSigner;
    private static final String VC_1 = """
            {
                            "@context": [
                                "https://www.w3.org/ns/credentials/v2"
                            ],
                            "validFrom": "2024-09-22T23:06:22.123Z",
                            "validUntil": "2034-09-22T23:06:22.123Z",
                            "type": [
                                "VerifiableCredential",
                                "MyPrototypeCredential"
                            ],
                            "credentialSubject": {
                                "mySubjectProperty": "mySubjectValue"
                            }
                        }
            """;
    private static final String VC_2 = """
            {
                            "@context": [
                                "https://www.w3.org/ns/credentials/v2"
                            ],
                            "issuanceDate": "2024-09-22T23:06:22.123Z",
                            "validUntil": "2034-09-22T23:06:22.123Z",
                            "type": [
                                "VerifiableCredential",
                                "MyPrototypeCredential"
                            ],
                            "credentialSubject": {
                                "mySubjectProperty": "mySubjectValue"
                            }
            }""";
    private static final String VC_3 = """
            {
                            "@context": [
                                "https://www.w3.org/ns/credentials/v2"
                            ],
                            "vcIssuanceDate": "2024-09-22T23:06:22.123Z",
                            "validUntil": "2034-09-22T23:06:22.123Z",
                            "type": [
                                "VerifiableCredential",
                                "MyPrototypeCredential"
                            ],
                            "credentialSubject": {
                                "mySubjectProperty": "mySubjectValue"
                            }
            }""";

    @Before
    public void setup() {
        ReflectionTestUtils.setField(jsonLDVCSigner, "didUrl", "https://example.com/sample.pub.key.json/");
        CertificateResponseDTO ecR1CertDto = new CertificateResponseDTO();
        ecR1CertDto.setCertificateData("-----BEGIN CERTIFICATE-----\nMIIDEDCCAfigAwIBAgIIZ1nHaUeKLDMwDQYJKoZIhvcNAQELBQAweDELMAkGA1UE\nBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoM\nBUlJSVRCMRcwFQYDVQQLDA5FWEFNUExFLUNFTlRFUjEfMB0GA1UEAwwWd3d3LmV4\nYW1wbGUuY29tIChST09UKTAeFw0yNTA0MDcwMTQ1MzVaFw0yODA0MDYwMTQ1MzVa\nMIGbMQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9S\nRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMUIwQAYD\nVQQDDDl3d3cuZXhhbXBsZS5jb20gKENFUlRJRllfVkNfU0lHTl9FQ19SMS1FQ19T\nRUNQMjU2UjFfU0lHTikwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARnZrptfF7k\nyWism4kK6l8N6K4v8H3FyYzlkDc8/mP55pa+gTUvcEN4DF7jAZntyYUL8GE3Eupf\nd2ZdL7ojg2sgo0UwQzASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBRIWCn1\nRWbTDjYmBJLsnQ5jKyYudzAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQAD\nggEBAIM3Mv1W3N5htKcNEhvtkRYhl0MthNRNzNOuNSRu8VHBgverGE438vdbCQ2f\n/CGBI+Jo2IHdsaFOFGvb6TOOjEZFPgGJyPBK1PGqZc/OiqIcLvPwQ0HVQbp6fgHC\nxocizOAZmrjCQSgQgcDQSuO9tv9JV3Vb7odnPFlbtpREN23AS4KMyVYRm06CrSac\nPW44fSP4GSbWHmgaBvhWxJcXJ/4LpK+UQ1Q0dszm6ofgppd18oSwix90NRDTej7J\nAXmfM3eCvGvMlJC3jHs4EFns9egC16hHqX7INpE1K/ZNyTgHhXpErqaDWw2xkkPC\nvVFPORPyyNumlhL/f36CtutMe2U=\n-----END CERTIFICATE-----\n");
        ecR1CertDto.setKeyId("EC_SECP256R1_SIGN");
        when(didDocumentUtil.getCertificateDataResponseDto(any(), any())).thenReturn(ecR1CertDto);
    }

    @Test
    public void testAttachSignatureSuccess_VC2() {
        // Mock Templated VC and Key Manager Input
        String VCs[] = new String[]{VC_1, VC_2, VC_3};
        for (String templatedVC : VCs) {
            // Prepare a FakeSignature2018 implementation
            JWTSignatureResponseDto jwsSignedData = new JWTSignatureResponseDto();
            jwsSignedData.setJwtSignedData("mocked-jws");
            when(signatureService.jwsSign(any())).thenReturn(jwsSignedData);
            when(signProps.getName()).thenReturn("FakeSignature2018");
            when(signProps.getCanonicalizer()).thenReturn(new URDNA2015Canonicalizer());
            LdProof l = LdProof.builder().jws("fake-jws-proof").type("FakeSignature2018").proofPurpose("assertionMethod").build();
            when(signProps.generateProof(any(), any(), any())).thenReturn(l);
            when(proofGeneratorFactory.getProofGenerator(any())).thenReturn(Optional.of(signProps));
            Map<String, String> defaultSettings = new HashMap<>();
            defaultSettings.put(Constants.APPLICATION_ID, "fake-application-id");
            defaultSettings.put(Constants.REFERENCE_ID, "fake-reference-id");
            // invoke
            VCResult<JsonLDObject> vcResult = jsonLDVCSigner.attachSignature(templatedVC, defaultSettings);

            // test
            assert vcResult != null;
            JsonLDObject credential = vcResult.getCredential();
            Assert.assertNotNull(credential.getJsonObject().containsKey("proof"));
            Map<String, Object> proof = (Map<String, Object>) credential.getJsonObject().get("proof");
            Assert.assertEquals("fake-jws-proof", proof.get("jws"));
        }
    }

    @Test(expected = CertifyException.class)
    public void testAttachSignature_CanonicalizationThrowsException() throws Exception {
        // Arrange
        String vc = """
        {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "issuanceDate": "2024-09-22T23:06:22.123Z",
            "type": ["VerifiableCredential"]
        }
    """;
        Map<String, String> keyDetails = new HashMap<>();

        // Act & Assert
        jsonLDVCSigner.attachSignature(vc, keyDetails);
    }

}