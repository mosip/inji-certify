package io.mosip.certify.credential;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.utils.MDocUtils;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.service.SignatureService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive tests for MDocCredential
 * Tests cover:
 * - Format handling
 * - Credential creation workflow
 * - Proof generation with COSE signing
 * - Error handling and edge cases
 * - ISO 18013-5 compliance
 */
@RunWith(MockitoJUnitRunner.class)
public class MDocCredentialTest {

    private MDocCredential mDocCredential;

    @Mock
    private VCFormatter vcFormatter;

    @Mock
    private SignatureService signatureService;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private MDocUtils mDocUtils;

    @Before
    public void setUp() {
        mDocCredential = new MDocCredential(vcFormatter, signatureService);
    }

    // ==================== Format Handling Tests ====================

    @Test
    public void testCanHandleReturnsTrueForMsoMdoc() {
        assertTrue("Should handle MSO_MDOC format",
                mDocCredential.canHandle(VCFormats.MSO_MDOC));
    }

    @Test
    public void testCanHandleReturnsFalseForOtherFormat() {
        assertFalse("Should not handle ldp_vc", mDocCredential.canHandle("ldp_vc"));
        assertFalse("Should not handle jwt_vc", mDocCredential.canHandle("jwt_vc"));
        assertFalse("Should not handle vc+sd-jwt", mDocCredential.canHandle("vc+sd-jwt"));
        assertFalse("Should not handle null", mDocCredential.canHandle(null));
    }

    // ==================== Credential Creation Tests ====================

    @Test
    public void testCreateCredentialWithValidInput() throws Exception {
        String templateName = "mDocTemplate";
        Map<String, Object> templateParams = new HashMap<>();
        templateParams.put("name", "John Doe");
        templateParams.put("age", 30);
        templateParams.put("didUrl", "https://issuer.example.com");

        String templatedJSON = "{\"docType\":\"org.iso.18013.5.1.mDL\",\"nameSpaces\":{}}";
        Map<String, Object> finalMDoc = new HashMap<>();
        finalMDoc.put("_docType", "org.iso.18013.5.1.mDL");
        finalMDoc.put("nameSpaces", new HashMap<>());
        String expectedResult = "{\"_docType\":\"org.iso.18013.5.1.mDL\",\"nameSpaces\":{}}";

        when(vcFormatter.format(templateParams)).thenReturn(templatedJSON);
        when(mDocUtils.processTemplatedJson(templatedJSON, templateParams)).thenReturn(finalMDoc);
        when(objectMapper.writeValueAsString(finalMDoc)).thenReturn(expectedResult);

        String result = mDocCredential.createCredential(templateParams, templateName);

        assertNotNull("Result should not be null", result);
        assertEquals("Result should match expected JSON", expectedResult, result);

        verify(vcFormatter).format(templateParams);
        verify(mDocUtils).processTemplatedJson(templatedJSON, templateParams);
        verify(objectMapper).writeValueAsString(finalMDoc);
    }

    @Test
    public void testCreateCredentialWithComplexTemplate() throws Exception {
        String templateName = "complexTemplate";
        Map<String, Object> templateParams = new HashMap<>();
        templateParams.put("familyName", "Doe");
        templateParams.put("givenName", "John");
        templateParams.put("birthDate", "1990-08-25");

        String templatedJSON = "{\"docType\":\"org.iso.18013.5.1.mDL\",\"nameSpaces\":{\"org.iso.18013.5.1\":[]}}";
        Map<String, Object> finalMDoc = new HashMap<>();
        finalMDoc.put("_docType", "org.iso.18013.5.1.mDL");
        Map<String, Object> nameSpaces = new HashMap<>();
        nameSpaces.put("org.iso.18013.5.1", new ArrayList<>());
        finalMDoc.put("nameSpaces", nameSpaces);

        when(vcFormatter.format(templateParams)).thenReturn(templatedJSON);
        when(mDocUtils.processTemplatedJson(templatedJSON, templateParams)).thenReturn(finalMDoc);
        when(objectMapper.writeValueAsString(finalMDoc)).thenReturn("{}");

        String result = mDocCredential.createCredential(templateParams, templateName);

        assertNotNull("Result should not be null", result);
        verify(mDocUtils).processTemplatedJson(templatedJSON, templateParams);
    }

    @Test(expected = CertifyException.class)
    public void testCreateCredentialThrowsExceptionWhenFormatterFails() throws Exception {
        String templateName = "badTemplate";
        Map<String, Object> templateParams = new HashMap<>();

        when(vcFormatter.format(templateParams))
                .thenThrow(new RuntimeException("Formatting failed"));

        mDocCredential.createCredential(templateParams, templateName);
    }

    @Test(expected = CertifyException.class)
    public void testCreateCredentialThrowsExceptionWhenProcessingFails() throws Exception {
        String templateName = "badTemplate";
        Map<String, Object> templateParams = new HashMap<>();
        String templatedJSON = "{\"docType\":\"org.iso.18013.5.1.mDL\"}";

        when(vcFormatter.format(templateParams)).thenReturn(templatedJSON);
        when(mDocUtils.processTemplatedJson(templatedJSON, templateParams))
                .thenThrow(new RuntimeException("Processing failed"));

        mDocCredential.createCredential(templateParams, templateName);
    }

    @Test(expected = CertifyException.class)
    public void testCreateCredentialThrowsExceptionWhenJsonSerializationFails() throws Exception {
        String templateName = "mDocTemplate";
        Map<String, Object> templateParams = new HashMap<>();
        String templatedJSON = "{\"docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> finalMDoc = new HashMap<>();

        when(vcFormatter.format(templateParams)).thenReturn(templatedJSON);
        when(mDocUtils.processTemplatedJson(templatedJSON, templateParams)).thenReturn(finalMDoc);
        when(objectMapper.writeValueAsString(finalMDoc))
                .thenThrow(new RuntimeException("Serialization failed"));

        mDocCredential.createCredential(templateParams, templateName);
    }

    // ==================== Proof Generation Tests ====================

    @Test
    public void testAddProofGeneratesCorrectVCResult() throws Exception {
        String vcToSign = "{\"_docType\":\"org.iso.18013.5.1.mDL\",\"nameSpaces\":{}}";
        String appID = "testApp";
        String refID = "testRef";
        String signAlgorithm = "ES256";
        String didUrl = "https://example.com/did";

        Map<String, Object> mDocJson = createTestMDocJson();
        Map<String, Object> saltedNamespaces = createTestSaltedNamespaces();
        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        Map<String, Object> taggedNamespaces = createTestTaggedNamespaces();
        Map<String, Object> mso = createTestMSO();
        byte[] signedMSO = new byte[]{1, 2, 3, 4};
        Map<String, Object> issuerSigned = createTestIssuerSigned();
        byte[] cborIssuerSigned = new byte[]{5, 6, 7, 8};

        try (MockedStatic<MDocUtils> mockedStatic = mockStatic(MDocUtils.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocUtils.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocUtils.calculateDigests(eq(saltedNamespaces), any()))
                    .thenReturn(taggedNamespaces);
            when(mDocUtils.createMobileSecurityObject(eq(mDocJson), any()))
                    .thenReturn(mso);
            when(mDocUtils.signMSO(mso, appID, refID, signAlgorithm))
                    .thenReturn(signedMSO);
            mockedStatic.when(() -> MDocUtils.createIssuerSignedStructure(taggedNamespaces, signedMSO))
                    .thenReturn(issuerSigned);
            mockedStatic.when(() -> MDocUtils.encodeToCBOR(issuerSigned))
                    .thenReturn(cborIssuerSigned);

            VCResult<?> result = mDocCredential.addProof(
                    vcToSign, null, signAlgorithm, appID, refID, didUrl, "Ed25519Signature2020"
            );

            assertNotNull("Result should not be null", result);
            assertEquals("Format should be MSO_MDOC", VCFormats.MSO_MDOC, result.getFormat());
            assertNotNull("Credential should not be null", result.getCredential());
            assertTrue("Credential should be a String", result.getCredential() instanceof String);

            verify(mDocUtils).createMobileSecurityObject(eq(mDocJson), any());
            verify(mDocUtils).signMSO(mso, appID, refID, signAlgorithm);
        }
    }

    @Test
    public void testAddProofReturnsBase64UrlEncodedCredential() throws Exception {
        String vcToSign = "{\"_docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = createTestMDocJson();
        Map<String, Object> saltedNamespaces = createTestSaltedNamespaces();
        Map<String, Object> taggedNamespaces = createTestTaggedNamespaces();
        Map<String, Object> mso = createTestMSO();
        byte[] signedMSO = new byte[]{1, 2, 3};
        Map<String, Object> issuerSigned = createTestIssuerSigned();
        byte[] cborIssuerSigned = "test data for base64url encoding".getBytes();

        try (MockedStatic<MDocUtils> mockedStatic = mockStatic(MDocUtils.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocUtils.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocUtils.calculateDigests(eq(saltedNamespaces), any()))
                    .thenReturn(taggedNamespaces);
            when(mDocUtils.createMobileSecurityObject(eq(mDocJson), any())).thenReturn(mso);
            when(mDocUtils.signMSO(eq(mso), anyString(), anyString(), anyString()))
                    .thenReturn(signedMSO);
            mockedStatic.when(() -> MDocUtils.createIssuerSignedStructure(any(), any()))
                    .thenReturn(issuerSigned);
            mockedStatic.when(() -> MDocUtils.encodeToCBOR(any())).thenReturn(cborIssuerSigned);

            VCResult<?> result = mDocCredential.addProof(
                    vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020"
            );

            assertNotNull("Credential should not be null", result.getCredential());
            String credential = (String) result.getCredential();

            // Verify it's Base64 URL encoded (no +, /, or = padding)
            assertFalse("Should not contain +", credential.contains("+"));
            assertFalse("Should not contain /", credential.contains("/"));
            assertFalse("Should not contain = padding", credential.contains("="));
        }
    }

    @Test
    public void testAddProofWithDifferentSignatureAlgorithms() throws Exception {
        String vcToSign = "{\"_docType\":\"org.iso.18013.5.1.mDL\"}";
        String[] algorithms = {"ES256", "ES384", "ES512"};

        for (String algorithm : algorithms) {
            Map<String, Object> mDocJson = createTestMDocJson();
            Map<String, Object> saltedNamespaces = createTestSaltedNamespaces();
            Map<String, Object> taggedNamespaces = createTestTaggedNamespaces();
            Map<String, Object> mso = createTestMSO();
            byte[] signedMSO = new byte[]{1, 2, 3};
            Map<String, Object> issuerSigned = createTestIssuerSigned();
            byte[] cborIssuerSigned = new byte[]{4, 5, 6};

            try (MockedStatic<MDocUtils> mockedStatic = mockStatic(MDocUtils.class)) {
                when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
                mockedStatic.when(() -> MDocUtils.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
                mockedStatic.when(() -> MDocUtils.calculateDigests(eq(saltedNamespaces), any()))
                        .thenReturn(taggedNamespaces);
                when(mDocUtils.createMobileSecurityObject(eq(mDocJson), any())).thenReturn(mso);
                when(mDocUtils.signMSO(eq(mso), anyString(), anyString(), eq(algorithm)))
                        .thenReturn(signedMSO);
                mockedStatic.when(() -> MDocUtils.createIssuerSignedStructure(any(), any()))
                        .thenReturn(issuerSigned);
                mockedStatic.when(() -> MDocUtils.encodeToCBOR(any())).thenReturn(cborIssuerSigned);

                VCResult<?> result = mDocCredential.addProof(
                        vcToSign, null, algorithm, "appID", "refID", "https://example.com/did", "Ed25519Signature2020"
                );

                assertNotNull("Result should not be null for " + algorithm, result);
                assertEquals("Format should be MSO_MDOC", VCFormats.MSO_MDOC, result.getFormat());
            }
        }
    }

    @Test
    public void testAddProofWithNullHeaders() throws Exception {
        String vcToSign = "{\"_docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = createTestMDocJson();
        Map<String, Object> saltedNamespaces = createTestSaltedNamespaces();
        Map<String, Object> taggedNamespaces = createTestTaggedNamespaces();
        Map<String, Object> mso = createTestMSO();
        byte[] signedMSO = new byte[]{1, 2, 3};
        Map<String, Object> issuerSigned = createTestIssuerSigned();
        byte[] cborIssuerSigned = new byte[]{4, 5, 6};

        try (MockedStatic<MDocUtils> mockedStatic = mockStatic(MDocUtils.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocUtils.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocUtils.calculateDigests(eq(saltedNamespaces), any()))
                    .thenReturn(taggedNamespaces);
            when(mDocUtils.createMobileSecurityObject(eq(mDocJson), any())).thenReturn(mso);
            when(mDocUtils.signMSO(eq(mso), anyString(), anyString(), anyString()))
                    .thenReturn(signedMSO);
            mockedStatic.when(() -> MDocUtils.createIssuerSignedStructure(any(), any()))
                    .thenReturn(issuerSigned);
            mockedStatic.when(() -> MDocUtils.encodeToCBOR(any())).thenReturn(cborIssuerSigned);

            VCResult<?> result = mDocCredential.addProof(
                    vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020"
            );

            assertNotNull("Result should not be null", result);
            assertEquals("Format should be MSO_MDOC", VCFormats.MSO_MDOC, result.getFormat());
        }
    }

    // ==================== Error Handling Tests ====================

    @Test(expected = CertifyException.class)
    public void testAddProofThrowsExceptionWhenJsonParsingFails() throws Exception {
        String vcToSign = "invalid json";
        String appID = "testApp";
        String refID = "testRef";

        when(objectMapper.readValue(vcToSign, Map.class))
                .thenThrow(new RuntimeException("JSON parsing failed"));

        mDocCredential.addProof(
                vcToSign, null, "ES256", appID, refID, "https://example.com/did", "Ed25519Signature2020"
        );
    }

    @Test(expected = CertifyException.class)
    public void testAddProofThrowsExceptionWhenSaltingFails() throws Exception {
        String vcToSign = "{\"_docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = createTestMDocJson();

        try (MockedStatic<MDocUtils> mockedStatic = mockStatic(MDocUtils.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocUtils.addRandomSalts(mDocJson))
                    .thenThrow(new RuntimeException("Salting failed"));

            mDocCredential.addProof(
                    vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020"
            );
        }
    }

    @Test(expected = CertifyException.class)
    public void testAddProofThrowsExceptionWhenDigestCalculationFails() throws Exception {
        String vcToSign = "{\"_docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = createTestMDocJson();
        Map<String, Object> saltedNamespaces = createTestSaltedNamespaces();

        try (MockedStatic<MDocUtils> mockedStatic = mockStatic(MDocUtils.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocUtils.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocUtils.calculateDigests(eq(saltedNamespaces), any()))
                    .thenThrow(new RuntimeException("Digest calculation failed"));

            mDocCredential.addProof(
                    vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020"
            );
        }
    }

    @Test(expected = CertifyException.class)
    public void testAddProofThrowsExceptionWhenMSOCreationFails() throws Exception {
        String vcToSign = "{\"_docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = createTestMDocJson();
        Map<String, Object> saltedNamespaces = createTestSaltedNamespaces();
        Map<String, Object> taggedNamespaces = createTestTaggedNamespaces();

        try (MockedStatic<MDocUtils> mockedStatic = mockStatic(MDocUtils.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocUtils.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocUtils.calculateDigests(eq(saltedNamespaces), any()))
                    .thenReturn(taggedNamespaces);
            when(mDocUtils.createMobileSecurityObject(any(), any()))
                    .thenThrow(new RuntimeException("MSO creation failed"));

            mDocCredential.addProof(
                    vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020"
            );
        }
    }

    @Test(expected = CertifyException.class)
    public void testAddProofThrowsExceptionWhenMSOSigningFails() throws Exception {
        String vcToSign = "{\"_docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = createTestMDocJson();
        Map<String, Object> saltedNamespaces = createTestSaltedNamespaces();
        Map<String, Object> taggedNamespaces = createTestTaggedNamespaces();
        Map<String, Object> mso = createTestMSO();

        try (MockedStatic<MDocUtils> mockedStatic = mockStatic(MDocUtils.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocUtils.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocUtils.calculateDigests(eq(saltedNamespaces), any()))
                    .thenReturn(taggedNamespaces);
            when(mDocUtils.createMobileSecurityObject(any(), any())).thenReturn(mso);
            when(mDocUtils.signMSO(any(), anyString(), anyString(), anyString()))
                    .thenThrow(new RuntimeException("MSO signing failed"));

            mDocCredential.addProof(
                    vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020"
            );
        }
    }

    @Test(expected = CertifyException.class)
    public void testAddProofThrowsExceptionWhenCBOREncodingFails() throws Exception {
        String vcToSign = "{\"_docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = createTestMDocJson();
        Map<String, Object> saltedNamespaces = createTestSaltedNamespaces();
        Map<String, Object> taggedNamespaces = createTestTaggedNamespaces();
        Map<String, Object> mso = createTestMSO();
        byte[] signedMSO = new byte[]{1, 2, 3};
        Map<String, Object> issuerSigned = createTestIssuerSigned();

        try (MockedStatic<MDocUtils> mockedStatic = mockStatic(MDocUtils.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocUtils.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocUtils.calculateDigests(eq(saltedNamespaces), any()))
                    .thenReturn(taggedNamespaces);
            when(mDocUtils.createMobileSecurityObject(any(), any())).thenReturn(mso);
            when(mDocUtils.signMSO(any(), anyString(), anyString(), anyString()))
                    .thenReturn(signedMSO);
            mockedStatic.when(() -> MDocUtils.createIssuerSignedStructure(any(), any()))
                    .thenReturn(issuerSigned);
            mockedStatic.when(() -> MDocUtils.encodeToCBOR(any()))
                    .thenThrow(new RuntimeException("CBOR encoding failed"));

            mDocCredential.addProof(
                    vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020"
            );
        }
    }

    @Test(expected = CertifyException.class)
    public void testAddProofThrowsExceptionWhenIssuerSignedStructureFails() throws Exception {
        String vcToSign = "{\"_docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = createTestMDocJson();
        Map<String, Object> saltedNamespaces = createTestSaltedNamespaces();
        Map<String, Object> taggedNamespaces = createTestTaggedNamespaces();
        Map<String, Object> mso = createTestMSO();
        byte[] signedMSO = new byte[]{1, 2, 3};

        try (MockedStatic<MDocUtils> mockedStatic = mockStatic(MDocUtils.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocUtils.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocUtils.calculateDigests(eq(saltedNamespaces), any()))
                    .thenReturn(taggedNamespaces);
            when(mDocUtils.createMobileSecurityObject(any(), any())).thenReturn(mso);
            when(mDocUtils.signMSO(any(), anyString(), anyString(), anyString()))
                    .thenReturn(signedMSO);
            mockedStatic.when(() -> MDocUtils.createIssuerSignedStructure(any(), any()))
                    .thenThrow(new RuntimeException("IssuerSigned structure creation failed"));

            mDocCredential.addProof(
                    vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020"
            );
        }
    }

    // ==================== Helper Methods ====================

    private Map<String, Object> createTestMDocJson() {
        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("_docType", "org.iso.18013.5.1.mDL");
        mDocJson.put("nameSpaces", new HashMap<>());
        return mDocJson;
    }

    private Map<String, Object> createTestSaltedNamespaces() {
        Map<String, Object> saltedNamespaces = new HashMap<>();
        List<Map<String, Object>> elements = new ArrayList<>();

        Map<String, Object> element = new HashMap<>();
        element.put("digestID", 0);
        element.put("elementIdentifier", "family_name");
        element.put("elementValue", "Doe");
        element.put("random", new byte[24]);
        elements.add(element);

        saltedNamespaces.put("org.iso.18013.5.1", elements);
        return saltedNamespaces;
    }

    private Map<String, Object> createTestTaggedNamespaces() {
        Map<String, Object> taggedNamespaces = new HashMap<>();
        taggedNamespaces.put("org.iso.18013.5.1", new ArrayList<>());
        return taggedNamespaces;
    }

    private Map<String, Object> createTestMSO() {
        Map<String, Object> mso = new HashMap<>();
        mso.put("version", "1.0");
        mso.put("digestAlgorithm", "SHA-256");
        mso.put("docType", "org.iso.18013.5.1.mDL");
        mso.put("valueDigests", new HashMap<>());
        mso.put("deviceKeyInfo", new HashMap<>());
        return mso;
    }

    private Map<String, Object> createTestIssuerSigned() {
        Map<String, Object> issuerSigned = new HashMap<>();
        issuerSigned.put("nameSpaces", new HashMap<>());
        issuerSigned.put("issuerAuth", new byte[]{1, 2, 3});
        return issuerSigned;
    }
}