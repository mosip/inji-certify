package io.mosip.certify.credential;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.utils.DIDDocumentUtil;
import io.mosip.certify.utils.MDocUtils;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.service.CoseSignatureService;
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

@RunWith(MockitoJUnitRunner.class)
public class MDocCredentialTest {

    @InjectMocks
    private MDocCredential mDocCredential;

    @Mock
    private VCFormatter vcFormatter;

    @Mock
    private SignatureService signatureService;

    @Mock
    private CoseSignatureService coseSignatureService;

    @Mock
    private DIDDocumentUtil didDocumentUtil;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private MDocUtils mDocUtils;

    @Before
    public void setUp() {
        ReflectionTestUtils.setField(mDocCredential, "coseSignatureService", coseSignatureService);
        ReflectionTestUtils.setField(mDocCredential, "didDocumentUtil", didDocumentUtil);
        ReflectionTestUtils.setField(mDocCredential, "objectMapper", objectMapper);
        ReflectionTestUtils.setField(mDocCredential, "mDocUtils", mDocUtils);
    }

    @Test
    public void testCanHandleReturnsTrueForMsoMdoc() {
        assertTrue(mDocCredential.canHandle(VCFormats.MSO_MDOC));
    }

    @Test
    public void testCanHandleReturnsFalseForOtherFormat() {
        assertFalse(mDocCredential.canHandle("ldp_vc"));
        assertFalse(mDocCredential.canHandle("jwt_vc"));
        assertFalse(mDocCredential.canHandle("vc+sd-jwt"));
    }

    @Test
    public void testCreateCredentialWithValidInput() throws Exception {
        String templateName = "mDocTemplate";
        Map<String, Object> templateParams = new HashMap<>();
        templateParams.put("name", "John Doe");
        templateParams.put("age", 30);

        String templatedJSON = "{\"docType\":\"org.iso.18013.5.1.mDL\",\"nameSpaces\":{}}";
        Map<String, Object> finalMDoc = new HashMap<>();
        finalMDoc.put("docType", "org.iso.18013.5.1.mDL");
        finalMDoc.put("nameSpaces", new HashMap<>());

        when(vcFormatter.format(templateParams)).thenReturn(templatedJSON);
        when(mDocUtils.processTemplatedJson(templatedJSON, templateParams)).thenReturn(finalMDoc);
        when(objectMapper.writeValueAsString(finalMDoc)).thenReturn("{\"docType\":\"org.iso.18013.5.1.mDL\"}");

        String result = mDocCredential.createCredential(templateParams, templateName);

        assertNotNull(result);
        verify(vcFormatter).format(templateParams);
        verify(mDocUtils).processTemplatedJson(templatedJSON, templateParams);
        verify(objectMapper).writeValueAsString(finalMDoc);
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

    @Test
    public void testAddProofGeneratesCorrectVCResult() throws Exception {
        String vcToSign = "{\"docType\":\"org.iso.18013.5.1.mDL\",\"nameSpaces\":{}}";
        String appID = "testApp";
        String refID = "testRef";
        String signAlgorithm = "ES256";
        String didUrl = "https://example.com/did";

        Map<String, Object> mDocJson = new HashMap<>();
        mDocJson.put("docType", "org.iso.18013.5.1.mDL");
        mDocJson.put("nameSpaces", new HashMap<>());

        Map<String, Object> saltedNamespaces = new HashMap<>();
        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        Map<String, Object> taggedNamespaces = new HashMap<>();
        Map<String, Object> mso = new HashMap<>();
        byte[] signedMSO = new byte[]{1, 2, 3, 4};
        Map<String, Object> issuerSigned = new HashMap<>();
        byte[] cborIssuerSigned = new byte[]{5, 6, 7, 8};

        try (MockedStatic<MDocUtils> mockedStatic = mockStatic(MDocUtils.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocUtils.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocUtils.calculateDigests(eq(saltedNamespaces), any()))
                    .thenReturn(taggedNamespaces);
            mockedStatic.when(() -> MDocUtils.createMobileSecurityObject(mDocJson, namespaceDigests))
                    .thenReturn(mso);
            mockedStatic.when(() -> MDocUtils.signMSO(mso, appID, refID, signAlgorithm, coseSignatureService))
                    .thenReturn(signedMSO);
            mockedStatic.when(() -> MDocUtils.createIssuerSignedStructure(taggedNamespaces, signedMSO))
                    .thenReturn(issuerSigned);
            mockedStatic.when(() -> MDocUtils.encodeToCBOR(issuerSigned)).thenReturn(cborIssuerSigned);

            VCResult<?> result = mDocCredential.addProof(vcToSign, null, signAlgorithm, appID, refID, didUrl, "Ed25519Signature2020");

            assertNotNull(result);
            assertEquals(VCFormats.MSO_MDOC, result.getFormat());
            assertNotNull(result.getCredential());
            assertTrue(result.getCredential() instanceof String);
        }
    }

    @Test(expected = CertifyException.class)
    public void testAddProofThrowsExceptionWhenJsonParsingFails() throws Exception {
        String vcToSign = "invalid json";
        String appID = "testApp";
        String refID = "testRef";

        when(objectMapper.readValue(vcToSign, Map.class))
                .thenThrow(new RuntimeException("JSON parsing failed"));

        mDocCredential.addProof(vcToSign, null, "ES256", appID, refID, "https://example.com/did", "Ed25519Signature2020");
    }

    @Test(expected = CertifyException.class)
    public void testAddProofThrowsExceptionWhenSaltingFails() throws Exception {
        String vcToSign = "{\"docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = new HashMap<>();

        try (MockedStatic<MDocUtils> mockedStatic = mockStatic(MDocUtils.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocUtils.addRandomSalts(mDocJson))
                    .thenThrow(new RuntimeException("Salting failed"));

            mDocCredential.addProof(vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020");
        }
    }

    @Test(expected = CertifyException.class)
    public void testAddProofThrowsExceptionWhenDigestCalculationFails() throws Exception {
        String vcToSign = "{\"docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = new HashMap<>();
        Map<String, Object> saltedNamespaces = new HashMap<>();

        try (MockedStatic<MDocUtils> mockedStatic = mockStatic(MDocUtils.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocUtils.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocUtils.calculateDigests(eq(saltedNamespaces), any()))
                    .thenThrow(new RuntimeException("Digest calculation failed"));

            mDocCredential.addProof(vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020");
        }
    }

    @Test(expected = CertifyException.class)
    public void testAddProofThrowsExceptionWhenMSOCreationFails() throws Exception {
        String vcToSign = "{\"docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = new HashMap<>();
        Map<String, Object> saltedNamespaces = new HashMap<>();
        Map<String, Object> taggedNamespaces = new HashMap<>();

        try (MockedStatic<MDocUtils> mockedStatic = mockStatic(MDocUtils.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocUtils.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocUtils.calculateDigests(eq(saltedNamespaces), any()))
                    .thenReturn(taggedNamespaces);
            mockedStatic.when(() -> MDocUtils.createMobileSecurityObject(any(), any(), anyString(), anyString()))
                    .thenThrow(new RuntimeException("MSO creation failed"));

            mDocCredential.addProof(vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020");
        }
    }

    @Test(expected = CertifyException.class)
    public void testAddProofThrowsExceptionWhenMSOSigningFails() throws Exception {
        String vcToSign = "{\"docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = new HashMap<>();
        Map<String, Object> saltedNamespaces = new HashMap<>();
        Map<String, Object> taggedNamespaces = new HashMap<>();
        Map<String, Object> mso = new HashMap<>();

        try (MockedStatic<MDocUtils> mockedStatic = mockStatic(MDocUtils.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocUtils.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocUtils.calculateDigests(eq(saltedNamespaces), any()))
                    .thenReturn(taggedNamespaces);
            mockedStatic.when(() -> MDocUtils.createMobileSecurityObject(any(), any(), anyString(), anyString()))
                    .thenReturn(mso);
            mockedStatic.when(() -> MDocUtils.signMSO(any(), anyString(), anyString(), anyString(), any(), any()))
                    .thenThrow(new RuntimeException("MSO signing failed"));

            mDocCredential.addProof(vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020");
        }
    }

    @Test(expected = CertifyException.class)
    public void testAddProofThrowsExceptionWhenCBOREncodingFails() throws Exception {
        String vcToSign = "{\"docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = new HashMap<>();
        Map<String, Object> saltedNamespaces = new HashMap<>();
        Map<String, Object> taggedNamespaces = new HashMap<>();
        Map<String, Object> mso = new HashMap<>();
        byte[] signedMSO = new byte[]{1, 2, 3};
        Map<String, Object> issuerSigned = new HashMap<>();

        try (MockedStatic<MDocUtils> mockedStatic = mockStatic(MDocUtils.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocUtils.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocUtils.calculateDigests(eq(saltedNamespaces), any()))
                    .thenReturn(taggedNamespaces);
            mockedStatic.when(() -> MDocUtils.createMobileSecurityObject(any(), any(), anyString(), anyString()))
                    .thenReturn(mso);
            mockedStatic.when(() -> MDocUtils.signMSO(any(), anyString(), anyString(), anyString(), any(), any()))
                    .thenReturn(signedMSO);
            mockedStatic.when(() -> MDocUtils.createIssuerSignedStructure(any(), any()))
                    .thenReturn(issuerSigned);
            mockedStatic.when(() -> MDocUtils.encodeToCBOR(any()))
                    .thenThrow(new RuntimeException("CBOR encoding failed"));

            mDocCredential.addProof(vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020");
        }
    }

    @Test
    public void testAddProofWithNullHeaders() throws Exception {
        String vcToSign = "{\"docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = new HashMap<>();
        Map<String, Object> saltedNamespaces = new HashMap<>();
        Map<String, Object> taggedNamespaces = new HashMap<>();
        Map<String, Object> mso = new HashMap<>();
        byte[] signedMSO = new byte[]{1, 2, 3};
        Map<String, Object> issuerSigned = new HashMap<>();
        byte[] cborIssuerSigned = new byte[]{4, 5, 6};

        try (MockedStatic<MDocUtils> mockedStatic = mockStatic(MDocUtils.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocUtils.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocUtils.calculateDigests(eq(saltedNamespaces), any()))
                    .thenReturn(taggedNamespaces);
            mockedStatic.when(() -> MDocUtils.createMobileSecurityObject(any(), any(), anyString(), anyString()))
                    .thenReturn(mso);
            mockedStatic.when(() -> MDocUtils.signMSO(any(), anyString(), anyString(), anyString(), any(), any()))
                    .thenReturn(signedMSO);
            mockedStatic.when(() -> MDocUtils.createIssuerSignedStructure(any(), any()))
                    .thenReturn(issuerSigned);
            mockedStatic.when(() -> MDocUtils.encodeToCBOR(any())).thenReturn(cborIssuerSigned);

            VCResult<?> result = mDocCredential.addProof(vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020");

            assertNotNull(result);
            assertEquals(VCFormats.MSO_MDOC, result.getFormat());
        }
    }

    @Test
    public void testAddProofWithDifferentSignatureAlgorithms() throws Exception {
        String vcToSign = "{\"docType\":\"org.iso.18013.5.1.mDL\"}";
        String[] algorithms = {"ES256", "ES384", "ES512", "RS256"};

        for (String algorithm : algorithms) {
            Map<String, Object> mDocJson = new HashMap<>();
            Map<String, Object> saltedNamespaces = new HashMap<>();
            Map<String, Object> taggedNamespaces = new HashMap<>();
            Map<String, Object> mso = new HashMap<>();
            byte[] signedMSO = new byte[]{1, 2, 3};
            Map<String, Object> issuerSigned = new HashMap<>();
            byte[] cborIssuerSigned = new byte[]{4, 5, 6};

            try (MockedStatic<MDocUtils> mockedStatic = mockStatic(MDocUtils.class)) {
                when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
                mockedStatic.when(() -> MDocUtils.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
                mockedStatic.when(() -> MDocUtils.calculateDigests(eq(saltedNamespaces), any()))
                        .thenReturn(taggedNamespaces);
                mockedStatic.when(() -> MDocUtils.createMobileSecurityObject(any(), any(), anyString(), anyString()))
                        .thenReturn(mso);
                mockedStatic.when(() -> MDocUtils.signMSO(any(), anyString(), anyString(), eq(algorithm), any(), any()))
                        .thenReturn(signedMSO);
                mockedStatic.when(() -> MDocUtils.createIssuerSignedStructure(any(), any()))
                        .thenReturn(issuerSigned);
                mockedStatic.when(() -> MDocUtils.encodeToCBOR(any())).thenReturn(cborIssuerSigned);

                VCResult<?> result = mDocCredential.addProof(vcToSign, null, algorithm, "appID", "refID", "https://example.com/did", "Ed25519Signature2020");

                assertNotNull(result);
                assertEquals(VCFormats.MSO_MDOC, result.getFormat());
            }
        }
    }

    @Test
    public void testAddProofReturnsBase64UrlEncodedCredential() throws Exception {
        String vcToSign = "{\"docType\":\"org.iso.18013.5.1.mDL\"}";
        Map<String, Object> mDocJson = new HashMap<>();
        Map<String, Object> saltedNamespaces = new HashMap<>();
        Map<String, Object> taggedNamespaces = new HashMap<>();
        Map<String, Object> mso = new HashMap<>();
        byte[] signedMSO = new byte[]{1, 2, 3};
        Map<String, Object> issuerSigned = new HashMap<>();
        byte[] cborIssuerSigned = "test data".getBytes();

        try (MockedStatic<MDocUtils> mockedStatic = mockStatic(MDocUtils.class)) {
            when(objectMapper.readValue(vcToSign, Map.class)).thenReturn(mDocJson);
            mockedStatic.when(() -> MDocUtils.addRandomSalts(mDocJson)).thenReturn(saltedNamespaces);
            mockedStatic.when(() -> MDocUtils.calculateDigests(eq(saltedNamespaces), any()))
                    .thenReturn(taggedNamespaces);
            mockedStatic.when(() -> MDocUtils.createMobileSecurityObject(any(), any(), anyString(), anyString()))
                    .thenReturn(mso);
            mockedStatic.when(() -> MDocUtils.signMSO(any(), anyString(), anyString(), anyString(), any(), any()))
                    .thenReturn(signedMSO);
            mockedStatic.when(() -> MDocUtils.createIssuerSignedStructure(any(), any()))
                    .thenReturn(issuerSigned);
            mockedStatic.when(() -> MDocUtils.encodeToCBOR(any())).thenReturn(cborIssuerSigned);

            VCResult<?> result = mDocCredential.addProof(vcToSign, null, "ES256", "appID", "refID", "https://example.com/did", "Ed25519Signature2020");

            assertNotNull(result.getCredential());
            String credential = (String) result.getCredential();
            // Verify it's Base64 URL encoded (no +, /, or = padding)
            assertFalse(credential.contains("+"));
            assertFalse(credential.contains("/"));
            assertFalse(credential.contains("="));
        }
    }
}