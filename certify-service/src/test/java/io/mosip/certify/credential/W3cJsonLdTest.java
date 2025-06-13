package io.mosip.certify.credential;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.JsonLdErrorCode;
import com.danubetech.dataintegrity.signer.LdSigner;
import com.danubetech.dataintegrity.signer.LdSignerRegistry;
import foundation.identity.jsonld.JsonLDException;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.credential.W3cJsonLd;
import io.mosip.certify.proofgenerators.ProofGenerator;
import io.mosip.certify.proofgenerators.dip.KeymanagerByteSigner;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.service.SignatureService;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.LdProof;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.kernel.signature.service.SignatureServicev2;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class W3cJsonLdTest {

    @InjectMocks
    private W3cJsonLd w3cJsonLd;

    @Mock
    private VCFormatter vcFormatter;

    @Mock
    private SignatureService signatureService;

    @Mock
    private SignatureServicev2 signatureServicev2;

    @Mock
    private ProofGenerator proofGenerator;

    @Before
    public void setUp() {
//        vcFormatter = mock(VCFormatter.class);
//        signatureService = mock(SignatureService.class);
//        proofGenerator = mock(ProofGenerator.class);
//
//        w3cJsonLd = new W3cJsonLd(vcFormatter, signatureService);
//        w3cJsonLd.proofGenerator = proofGenerator;

        ReflectionTestUtils.setField(w3cJsonLd, "proofGenerator", proofGenerator);
        ReflectionTestUtils.setField(w3cJsonLd, "dataIntegrityCryptoSuite", "");
    }

    @Test
    public void testCanHandleReturnsTrueForLdpVc() {
        assertTrue(w3cJsonLd.canHandle("ldp_vc"));
    }

    @Test
    public void testCanHandleReturnsFalseForOtherFormat() {
        assertFalse(w3cJsonLd.canHandle("jwt_vc"));
    }

    @Test
    public void testAddProofGeneratesCorrectVCResult() throws Exception {
        String vcJson = "{\"@context\":[],\"issuanceDate\":\"2023-01-01T00:00:00.000Z\"}";
        JsonLDObject jsonLDObject = JsonLDObject.fromJson(vcJson);

        Canonicalizer canonicalizer = mock(Canonicalizer.class);
        when(proofGenerator.getCanonicalizer()).thenReturn(canonicalizer);
        when(proofGenerator.getName()).thenReturn("RsaSignature2018");
        when(canonicalizer.canonicalize(any(LdProof.class), any(JsonLDObject.class)))
                .thenReturn("canonicalized".getBytes());

        LdProof ldProof = LdProof.builder()
                .type("RsaSignature2018")
                .created(new Date())
                .proofPurpose("assertionMethod")
                .verificationMethod(URI.create("https://example.com/key"))
                .build();

        when(proofGenerator.generateProof(any(LdProof.class), anyString(), anyMap())).thenReturn(ldProof);

        VCResult<?> result = w3cJsonLd.addProof(vcJson, null, "RS256", "appID", "refID", "https://example.com/key");

        assertEquals("ldp_vc", result.getFormat());
        assertNotNull(result.getCredential());
    }

    @Test
    public void testAddProofGeneratesCorrectVCResult_ValidFrom() throws Exception {
        String vcJson = "{\"@context\":[],\"validFrom\":\"2023-01-01T00:00:00.000Z\"}";
        JsonLDObject jsonLDObject = JsonLDObject.fromJson(vcJson);

        Canonicalizer canonicalizer = mock(Canonicalizer.class);
        when(proofGenerator.getCanonicalizer()).thenReturn(canonicalizer);
        when(proofGenerator.getName()).thenReturn("RsaSignature2018");
        when(canonicalizer.canonicalize(any(LdProof.class), any(JsonLDObject.class)))
                .thenReturn("canonicalized".getBytes());

        LdProof ldProof = LdProof.builder()
                .type("RsaSignature2018")
                .created(new Date())
                .proofPurpose("assertionMethod")
                .verificationMethod(URI.create("https://example.com/key"))
                .build();

        when(proofGenerator.generateProof(any(LdProof.class), anyString(), anyMap())).thenReturn(ldProof);

        VCResult<?> result = w3cJsonLd.addProof(vcJson, null, "RS256", "appID", "refID", "https://example.com/key");

        assertEquals("ldp_vc", result.getFormat());
        assertNotNull(result.getCredential());
    }

    @Test
    public void testAddProof_UsesCurrentTimeWhenNoDateProvided() throws Exception {
        String vcJson = "{\"@context\":[],\"id\":\"some-vc\"}"; // no issuanceDate or validFrom

        JsonLDObject jsonLDObject = JsonLDObject.fromJson(vcJson);

        Canonicalizer canonicalizer = mock(Canonicalizer.class);
        when(proofGenerator.getCanonicalizer()).thenReturn(canonicalizer);
        when(proofGenerator.getName()).thenReturn("TestProof");
        when(canonicalizer.canonicalize(any(LdProof.class), any(JsonLDObject.class)))
                .thenReturn("test".getBytes());

        LdProof ldProof = LdProof.builder()
                .type("TestProof")
                .created(new Date())
                .proofPurpose("assertionMethod")
                .verificationMethod(URI.create("https://example.com/key"))
                .build();

        when(proofGenerator.generateProof(any(), any(), anyMap())).thenReturn(ldProof);

        VCResult<?> result = w3cJsonLd.addProof(vcJson, null, "RS256", "appID", "refID", "https://example.com/key");

        assertNotNull(result);
        assertEquals("ldp_vc", result.getFormat());
        assertNotNull(result.getCredential());
    }

    @Test(expected = CertifyException.class)
    public void testAddProof_WhenCanonicalizerFails_ThrowsCertifyException() throws Exception {
        String vcJson = "{\"@context\":[],\"issuanceDate\":\"2023-01-01T00:00:00.000Z\"}";

        JsonLDObject jsonLDObject = JsonLDObject.fromJson(vcJson);

        Canonicalizer canonicalizer = mock(Canonicalizer.class);
        when(proofGenerator.getCanonicalizer()).thenReturn(canonicalizer);
        when(proofGenerator.getName()).thenReturn("TestProof");
        when(canonicalizer.canonicalize(any(LdProof.class), any(JsonLDObject.class)))
                .thenThrow(new IOException("Mocked IO failure"));

        // This will trigger the catch and rethrow CertifyException
        w3cJsonLd.addProof(vcJson, null, "RS256", "appID", "refID", "https://example.com/key");
    }

    @Test
    public void testAddProof_DataIntegrityCryptoSuitePath() throws Exception {
        // Set up to use dataIntegrityCryptoSuite path
        ReflectionTestUtils.setField(w3cJsonLd, "dataIntegrityCryptoSuite", "test-suite");

        // Mock LdSignerRegistry and dependencies
        LdSigner signer = mock(LdSigner.class);
        KeymanagerByteSigner keymanagerByteSigner = mock(KeymanagerByteSigner.class);
        com.danubetech.dataintegrity.canonicalizer.Canonicalizer canonicalizer = mock(com.danubetech.dataintegrity.canonicalizer.Canonicalizer.class);

        // Mock static method
        try (MockedStatic<LdSignerRegistry> registry = mockStatic(LdSignerRegistry.class)) {
            registry.when(() -> LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm(anyString())).thenReturn(signer);

            when(signer.getCanonicalizer(any())).thenReturn(canonicalizer);
            doNothing().when(signer).setSigner(any());
            doNothing().when(signer).setCryptosuite(anyString());
            doNothing().when(signer).initialize(any());
            doNothing().when(signer).sign(any(), any());

            when(canonicalizer.canonicalize(any(), any())).thenReturn("canonicalized".getBytes());

            String vcJson = "{\"@context\":[],\"issuanceDate\":\"2023-01-01T00:00:00.000Z\"}";
            VCResult<?> result = w3cJsonLd.addProof(vcJson, null, "RS256", "appID", "refID", "https://example.com/key");

            assertNotNull(result);
            assertEquals("ldp_vc", result.getFormat());
            assertNotNull(result.getCredential());
        }
    }

    @Test
    public void testAddProof_NullHeaders() throws Exception {
        String vcJson = "{\"@context\":[],\"issuanceDate\":\"2023-01-01T00:00:00.000Z\"}";
        Canonicalizer canonicalizer = mock(Canonicalizer.class);
        when(proofGenerator.getCanonicalizer()).thenReturn(canonicalizer);
        when(proofGenerator.getName()).thenReturn("RsaSignature2018");
        when(canonicalizer.canonicalize(any(LdProof.class), any(JsonLDObject.class)))
                .thenReturn("canonicalized".getBytes());

        LdProof ldProof = LdProof.builder()
                .type("RsaSignature2018")
                .created(new Date())
                .proofPurpose("assertionMethod")
                .verificationMethod(URI.create("https://example.com/key"))
                .build();

        when(proofGenerator.generateProof(any(LdProof.class), anyString(), anyMap())).thenReturn(ldProof);

        VCResult<?> result = w3cJsonLd.addProof(vcJson, null, "RS256", "appID", "refID", "https://example.com/key");
        assertNotNull(result);
        assertEquals("ldp_vc", result.getFormat());
    }

    @Test(expected = CertifyException.class)
    public void testAddProof_DataIntegrityCryptoSuitePath_CanonicalizerThrows() throws Exception {
        ReflectionTestUtils.setField(w3cJsonLd, "dataIntegrityCryptoSuite", "test-suite");

        LdSigner signer = mock(LdSigner.class);
        com.danubetech.dataintegrity.canonicalizer.Canonicalizer canonicalizer = mock(com.danubetech.dataintegrity.canonicalizer.Canonicalizer.class);

        try (MockedStatic<LdSignerRegistry> registry = mockStatic(LdSignerRegistry.class)) {
            registry.when(() -> LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm(anyString())).thenReturn(signer);

            when(signer.getCanonicalizer(any())).thenReturn(canonicalizer);
            doNothing().when(signer).setSigner(any());
            doNothing().when(signer).setCryptosuite(anyString());
            doNothing().when(signer).initialize(any());

            when(canonicalizer.canonicalize(any(), any())).thenThrow(new IOException("Mocked IO failure"));

            String vcJson = "{\"@context\":[],\"issuanceDate\":\"2023-01-01T00:00:00.000Z\"}";
            w3cJsonLd.addProof(vcJson, null, "RS256", "appID", "refID", "https://example.com/key");
        }
    }

    @Test(expected = CertifyException.class)
    public void testAddProof_DataIntegrityCryptoSuitePath_SignerInitializerThrows() throws Exception {
        ReflectionTestUtils.setField(w3cJsonLd, "dataIntegrityCryptoSuite", "test-suite");

        LdSigner signer = mock(LdSigner.class);
        com.danubetech.dataintegrity.canonicalizer.Canonicalizer canonicalizer = mock(com.danubetech.dataintegrity.canonicalizer.Canonicalizer.class);

        try (MockedStatic<LdSignerRegistry> registry = mockStatic(LdSignerRegistry.class)) {
            registry.when(() -> LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm(anyString())).thenReturn(signer);

            doNothing().when(signer).setSigner(any());
            doNothing().when(signer).setCryptosuite(anyString());
            doThrow(new GeneralSecurityException("Signer Initialization failed.")).when(signer).initialize(any());


            String vcJson = "{\"@context\":[],\"issuanceDate\":\"2023-01-01T00:00:00.000Z\"}";
            w3cJsonLd.addProof(vcJson, null, "RS256", "appID", "refID", "https://example.com/key");
        }
    }

    @Test(expected = CertifyException.class)
    public void testAddProof_DataIntegrityCryptoSuitePath_CanonicalizerThrowsSecurityException() throws Exception {
        ReflectionTestUtils.setField(w3cJsonLd, "dataIntegrityCryptoSuite", "test-suite");

        LdSigner signer = mock(LdSigner.class);
        com.danubetech.dataintegrity.canonicalizer.Canonicalizer canonicalizer = mock(com.danubetech.dataintegrity.canonicalizer.Canonicalizer.class);

        try (MockedStatic<LdSignerRegistry> registry = mockStatic(LdSignerRegistry.class)) {
            registry.when(() -> LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm(anyString())).thenReturn(signer);

            when(signer.getCanonicalizer(any())).thenReturn(canonicalizer);
            doNothing().when(signer).setSigner(any());
            doNothing().when(signer).setCryptosuite(anyString());
            doNothing().when(signer).initialize(any());

            when(canonicalizer.canonicalize(any(), any())).thenThrow(new GeneralSecurityException("Mocked IO failure"));

            String vcJson = "{\"@context\":[],\"issuanceDate\":\"2023-01-01T00:00:00.000Z\"}";
            w3cJsonLd.addProof(vcJson, null, "RS256", "appID", "refID", "https://example.com/key");
        }
    }

    @Test(expected = CertifyException.class)
    public void testAddProof_DataIntegrityCryptoSuitePath_CanonicalizerThrowsJsonLdException() throws Exception {
        ReflectionTestUtils.setField(w3cJsonLd, "dataIntegrityCryptoSuite", "test-suite");

        LdSigner signer = mock(LdSigner.class);
        com.danubetech.dataintegrity.canonicalizer.Canonicalizer canonicalizer = mock(com.danubetech.dataintegrity.canonicalizer.Canonicalizer.class);

        try (MockedStatic<LdSignerRegistry> registry = mockStatic(LdSignerRegistry.class)) {
            registry.when(() -> LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm(anyString())).thenReturn(signer);

            when(signer.getCanonicalizer(any())).thenReturn(canonicalizer);
            doNothing().when(signer).setSigner(any());
            doNothing().when(signer).setCryptosuite(anyString());
            doNothing().when(signer).initialize(any());

            when(canonicalizer.canonicalize(any(), any())).thenThrow(new JsonLDException(new JsonLdError(JsonLdErrorCode.CONFLICTING_INDEXES)));

            String vcJson = "{\"@context\":[],\"issuanceDate\":\"2023-01-01T00:00:00.000Z\"}";
            w3cJsonLd.addProof(vcJson, null, "RS256", "appID", "refID", "https://example.com/key");
        }
    }
}
