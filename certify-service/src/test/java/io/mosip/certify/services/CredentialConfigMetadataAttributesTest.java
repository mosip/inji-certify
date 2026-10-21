package io.mosip.certify.services;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.CredentialConfigurationSupportedDTO;
import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.dto.MetaDataDisplayDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.CredentialConfigValidationException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.CredentialConfigMapper;
import io.mosip.certify.utils.CredentialConfigMetadataResolver;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.*;
import java.util.function.Consumer;

import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Covers the per-credential-configuration selection of cryptographic_binding_methods_supported,
 * credential_signing_alg_values_supported and proof_types_supported: the binding methods and proof types
 * are mandatory in the request, the signing algorithm is the configuration's mandatory signatureAlgo,
 * what is accepted is stored exactly as requested with nothing filled in from the deployment
 * configuration, what is rejected, and what reaches the Get response and the credential issuer metadata.
 */
@RunWith(MockitoJUnitRunner.class)
public class CredentialConfigMetadataAttributesTest {

    @Mock
    private CredentialConfigRepository credentialConfigRepository;

    @Mock
    private CredentialConfigMapper credentialConfigMapper;

    @InjectMocks
    private CredentialConfigurationServiceImpl credentialConfigurationService;

    private static final String PROOF_SIGNING_ALGS = Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED;

    private static final Map<String, Consumer<CredentialConfigurationDTO>> CLEAR_ATTRIBUTE = Map.of(
            "cryptographicBindingMethodsSupported", dto -> dto.setCryptographicBindingMethodsSupported(null),
            "proofTypesSupported", dto -> dto.setProofTypesSupported(null));

    private static final Map<String, Consumer<CredentialConfigurationDTO>> EMPTY_ATTRIBUTE = Map.of(
            "cryptographicBindingMethodsSupported", dto -> dto.setCryptographicBindingMethodsSupported(List.of()),
            "proofTypesSupported", dto -> dto.setProofTypesSupported(Map.of()));

    @Before
    public void setup() {
        LinkedHashMap<String, List<String>> bindingMethods = new LinkedHashMap<>();
        bindingMethods.put("ldp_vc", List.of("did:jwk", "did:web"));
        bindingMethods.put("mso_mdoc", List.of("cose_key"));
        bindingMethods.put("dc+sd-jwt", List.of("did:jwk", "did:web"));

        LinkedHashMap<String, List<String>> signingAlgs = new LinkedHashMap<>();
        signingAlgs.put("Ed25519Signature2020", List.of("EdDSA"));
        signingAlgs.put("RsaSignature2018", List.of("RS256"));
        signingAlgs.put("EcdsaSecp256r1Signature2019", List.of("ES256"));

        LinkedHashMap<String, Object> proofTypes = new LinkedHashMap<>();
        proofTypes.put("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("RS256", "PS256", "ES256", "EdDSA")));

        Map<String, List<List<String>>> keyAliasMapper = new HashMap<>();
        keyAliasMapper.put("EdDSA", List.of(List.of("TEST2019", "TEST2019-REF")));
        keyAliasMapper.put("ES256", List.of(List.of("TEST_EC", "TEST_EC-REF")));

        ReflectionTestUtils.setField(credentialConfigurationService, "credentialIssuer", "http://example.com/");
        ReflectionTestUtils.setField(credentialConfigurationService, "authUrl", "http://auth.com");
        ReflectionTestUtils.setField(credentialConfigurationService, "servletPath", "v1/test");
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "DataProvider");
        ReflectionTestUtils.setField(credentialConfigurationService, "issuerDisplay", List.of(Map.of()));
        ReflectionTestUtils.setField(credentialConfigurationService, "cryptographicBindingMethodsSupportedMap", bindingMethods);
        declareSigningAlgs(signingAlgs);
        ReflectionTestUtils.setField(credentialConfigurationService, "proofTypesSupported", proofTypes);
        ReflectionTestUtils.setField(credentialConfigurationService, "keyAliasMapper", keyAliasMapper);
        ReflectionTestUtils.setField(credentialConfigurationService, "authorizationServerMapping", Map.of());
    }

    /**
     * An ldp_vc configuration without the binding methods and proof types, as the mapper returns one
     * created before they were stored.
     */
    private CredentialConfigurationDTO ldpVcConfig() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId("test-credential");
        dto.setMetaDataDisplay(List.of(new MetaDataDisplayDTO()));
        dto.setVcTemplate("test_template");
        dto.setCredentialFormat("ldp_vc");
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential", "TestVerifiableCredential"));
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setSignatureAlgo("EdDSA");
        dto.setKeyManagerAppId("TEST2019");
        dto.setKeyManagerRefId("TEST2019-REF");
        return dto;
    }

    /**
     * A valid ldp_vc request, carrying both attributes and its signatureAlgo.
     */
    private CredentialConfigurationDTO ldpVcRequest() {
        CredentialConfigurationDTO dto = ldpVcConfig();
        dto.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        dto.setProofTypesSupported(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA"))));
        return dto;
    }

    private CredentialConfig ldpVcEntity() {
        CredentialConfig entity = new CredentialConfig();
        entity.setCredentialConfigKeyId("test-credential");
        entity.setStatus("active");
        entity.setCredentialFormat("ldp_vc");
        entity.setSignatureCryptoSuite("Ed25519Signature2020");
        entity.setSignatureAlgo("EdDSA");
        return entity;
    }

    private CredentialConfigurationDTO sdJwtConfig() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId("test-sd-jwt");
        dto.setMetaDataDisplay(List.of(new MetaDataDisplayDTO()));
        dto.setVcTemplate("test_template");
        dto.setCredentialFormat("dc+sd-jwt");
        dto.setSdJwtVct("test-vct");
        dto.setSignatureAlgo("ES256");
        return dto;
    }

    private CredentialConfigurationDTO sdJwtRequest() {
        CredentialConfigurationDTO dto = sdJwtConfig();
        dto.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        dto.setProofTypesSupported(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("ES256"))));
        return dto;
    }

    private CredentialConfig sdJwtEntity() {
        CredentialConfig entity = new CredentialConfig();
        entity.setCredentialConfigKeyId("test-sd-jwt");
        entity.setStatus("active");
        entity.setCredentialFormat("dc+sd-jwt");
        entity.setSdJwtVct("test-vct");
        entity.setSignatureAlgo("ES256");
        return entity;
    }

    private CredentialConfigurationDTO msoMdocConfig() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId("test-mso-mdoc");
        dto.setMetaDataDisplay(List.of(new MetaDataDisplayDTO()));
        dto.setVcTemplate("test_template");
        dto.setCredentialFormat("mso_mdoc");
        dto.setDocType("org.iso.18013.5.1.mDL");
        dto.setSignatureAlgo("ES256");
        dto.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        return dto;
    }

    private CredentialConfigurationDTO msoMdocRequest() {
        CredentialConfigurationDTO dto = msoMdocConfig();
        dto.setCryptographicBindingMethodsSupported(List.of("cose_key"));
        dto.setProofTypesSupported(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("ES256"))));
        return dto;
    }

    private CredentialConfig msoMdocEntity() {
        CredentialConfig entity = new CredentialConfig();
        entity.setCredentialConfigKeyId("test-mso-mdoc");
        entity.setStatus("active");
        entity.setCredentialFormat("mso_mdoc");
        entity.setDocType("org.iso.18013.5.1.mDL");
        entity.setSignatureAlgo("ES256");
        return entity;
    }

    private CredentialConfig storedLdpVcEntity() {
        CredentialConfig stored = ldpVcEntity();
        stored.setCryptographicBindingMethodsSupported(List.of("did:jwk", "did:web"));
        stored.setCredentialSigningAlgValuesSupported(List.of("EdDSA"));
        stored.setProofTypesSupported(new LinkedHashMap<>(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("RS256", "EdDSA")))));
        return stored;
    }

    private void stubUpdateOf(CredentialConfig stored) {
        when(credentialConfigRepository.findByCredentialConfigKeyId("test-credential")).thenReturn(Optional.of(stored));
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(ldpVcConfig());
        doNothing().when(credentialConfigMapper).updateEntityFromDto(any(CredentialConfigurationDTO.class), any(CredentialConfig.class));
    }

    private static void assertRejectedAsInvalidRequestNaming(CredentialConfigValidationException exception, String attribute) {
        Assert.assertEquals(1, exception.getErrors().size());
        Assert.assertEquals(ErrorConstants.INVALID_REQUEST, exception.getErrors().getFirst().getErrorCode());
        Assert.assertTrue(exception.getErrors().getFirst().getErrorMessage().contains(attribute));
    }

    // ---------- Both attributes are mandatory on add: missing, null and empty are rejected alike ----------

    /**
     * Jackson binds a missing attribute and one sent as null to the same null, so this covers both.
     * Nothing is filled in from the deployment configuration in its place.
     */
    @Test
    public void should_rejectAdd_when_anyAttributeIsMissingOrNull() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());

        CLEAR_ATTRIBUTE.forEach((attribute, clear) -> {
            CredentialConfigurationDTO request = ldpVcRequest();
            clear.accept(request);

            CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                    () -> credentialConfigurationService.addCredentialConfiguration(request));

            assertRejectedAsInvalidRequestNaming(exception, attribute);
        });
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    @Test
    public void should_rejectAdd_when_anyAttributeIsEmpty() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());

        EMPTY_ATTRIBUTE.forEach((attribute, empty) -> {
            CredentialConfigurationDTO request = ldpVcRequest();
            empty.accept(request);

            CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                    () -> credentialConfigurationService.addCredentialConfiguration(request));

            assertRejectedAsInvalidRequestNaming(exception, attribute);
        });
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * A request written before the attributes were mandatory sends neither of them, and is told about
     * both at once.
     */
    @Test
    public void should_reportEachAttribute_when_bothAreMissing() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(ldpVcConfig()));

        Assert.assertEquals(2, exception.getErrors().size());
        exception.getErrors().forEach(error ->
                Assert.assertEquals(ErrorConstants.INVALID_REQUEST, error.getErrorCode()));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    // ---------- The signing algorithm is mandatory and never filled in ----------

    /**
     * An ldp_vc configuration used to take the first algorithm the deployment declares for its crypto
     * suite when signatureAlgo was left out. It is now rejected instead.
     */
    @Test
    public void should_rejectAdd_when_ldpVcSignatureAlgoIsMissing() {
        for (String missing : Arrays.asList(null, "")) {
            CredentialConfigurationDTO request = ldpVcRequest();
            request.setSignatureAlgo(missing);

            CertifyException exception = assertThrows(CertifyException.class,
                    () -> credentialConfigurationService.addCredentialConfiguration(request));

            Assert.assertEquals(ErrorConstants.LDP_VC_MANDATORY_FIELDS_MISSING, exception.getErrorCode());
            Assert.assertTrue(exception.getMessage().contains("signatureAlgo"));
            // Nothing is filled in from the deployment configuration.
            Assert.assertEquals(missing, request.getSignatureAlgo());
        }
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * An mdoc is signed with signatureAlgo alone, so the format requires it in place of a crypto suite.
     */
    @Test
    public void should_rejectAdd_when_msoMdocSignatureAlgoIsMissing() {
        CredentialConfigurationDTO request = msoMdocRequest();
        request.setSignatureAlgo(null);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(ErrorConstants.MSO_MDOC_MANDATORY_FIELDS_MISSING, exception.getErrorCode());
        Assert.assertTrue(exception.getMessage().contains("signatureAlgo"));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * An mdoc is signed with signatureAlgo alone, so a crypto suite sent with it is not validated - any
     * value is accepted - and is not stored. The configuration advertises its signatureAlgo.
     */
    @Test
    public void should_acceptMsoMdocAndStoreNoSuite_when_signatureCryptoSuiteIsSent() {
        for (String suite : List.of("EcdsaSecp256r1Signature2019", "NotADeclaredSuite")) {
            CredentialConfig entity = msoMdocEntity();
            entity.setSignatureCryptoSuite(suite);
            when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
            when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);
            CredentialConfigurationDTO request = msoMdocRequest();
            request.setSignatureCryptoSuite(suite);

            credentialConfigurationService.addCredentialConfiguration(request);

            Assert.assertNull(entity.getSignatureCryptoSuite());
            Assert.assertEquals(List.of("ES256"), entity.getCredentialSigningAlgValuesSupported());
        }
        verify(credentialConfigRepository, times(2)).save(any(CredentialConfig.class));
    }

    /**
     * Update replaces the stored configuration, so the suite sent on update is not stored either, and one
     * stored before the suite was ignored is cleared.
     */
    @Test
    public void should_acceptMsoMdocUpdateAndStoreNoSuite_when_signatureCryptoSuiteIsSent() {
        CredentialConfig stored = msoMdocEntity();
        stored.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        CredentialConfigurationDTO merged = msoMdocConfig();
        merged.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        when(credentialConfigRepository.findByCredentialConfigKeyId("test-mso-mdoc")).thenReturn(Optional.of(stored));
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(merged);
        doNothing().when(credentialConfigMapper).updateEntityFromDto(any(CredentialConfigurationDTO.class), any(CredentialConfig.class));
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(stored);
        CredentialConfigurationDTO request = msoMdocRequest();
        request.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");

        credentialConfigurationService.updateCredentialConfiguration("test-mso-mdoc", request);

        Assert.assertNull(stored.getSignatureCryptoSuite());
        Assert.assertEquals(List.of("ES256"), stored.getCredentialSigningAlgValuesSupported());
        verify(credentialConfigRepository).save(stored);
    }

    /**
     * The crypto suite is optional for mso_mdoc, so a request without one is accepted.
     */
    @Test
    public void should_acceptMsoMdocAndStoreNoSuite_when_signatureCryptoSuiteIsMissingOrEmpty() {
        for (String suite : Arrays.asList(null, "")) {
            CredentialConfig entity = msoMdocEntity();
            entity.setSignatureCryptoSuite(suite);
            when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
            when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);
            CredentialConfigurationDTO request = msoMdocRequest();
            request.setSignatureCryptoSuite(suite);

            credentialConfigurationService.addCredentialConfiguration(request);

            Assert.assertNull(entity.getSignatureCryptoSuite());
            Assert.assertEquals(List.of("ES256"), entity.getCredentialSigningAlgValuesSupported());
        }
        verify(credentialConfigRepository, times(2)).save(any(CredentialConfig.class));
    }

    /**
     * In VCIssuance mode the plugin signs the credential, so signatureAlgo is optional for every format.
     * An ldp_vc configuration still advertises its crypto suite; the others have no algorithm to advertise.
     */
    @Test
    public void should_acceptAdd_when_signatureAlgoIsMissingInVcIssuanceMode() {
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "VCIssuance");
        CredentialConfig ldpVc = ldpVcEntity();
        ldpVc.setSignatureAlgo(null);
        CredentialConfig msoMdoc = msoMdocEntity();
        msoMdoc.setSignatureAlgo(null);
        CredentialConfig sdJwt = sdJwtEntity();
        sdJwt.setSignatureAlgo(null);
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVc, msoMdoc, sdJwt);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenAnswer(invocation -> invocation.getArgument(0));
        CredentialConfigurationDTO ldpVcRequest = ldpVcRequest();
        ldpVcRequest.setSignatureAlgo(null);
        CredentialConfigurationDTO msoMdocRequest = msoMdocRequest();
        msoMdocRequest.setSignatureAlgo(null);
        CredentialConfigurationDTO sdJwtRequest = sdJwtRequest();
        sdJwtRequest.setSignatureAlgo(null);

        credentialConfigurationService.addCredentialConfiguration(ldpVcRequest);
        credentialConfigurationService.addCredentialConfiguration(msoMdocRequest);
        credentialConfigurationService.addCredentialConfiguration(sdJwtRequest);

        Assert.assertNull(ldpVc.getSignatureAlgo());
        Assert.assertEquals(List.of("Ed25519Signature2020"), ldpVc.getCredentialSigningAlgValuesSupported());
        Assert.assertNull(msoMdoc.getSignatureAlgo());
        Assert.assertEquals(List.of(), msoMdoc.getCredentialSigningAlgValuesSupported());
        Assert.assertNull(sdJwt.getSignatureAlgo());
        Assert.assertEquals(List.of(), sdJwt.getCredentialSigningAlgValuesSupported());
        verify(credentialConfigRepository, times(3)).save(any(CredentialConfig.class));
    }

    @Test
    public void should_rejectAdd_when_sdJwtSignatureAlgoIsMissingInDataProviderMode() {
        CredentialConfigurationDTO request = sdJwtRequest();
        request.setSignatureAlgo(null);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(ErrorConstants.DC_SD_JWT_MANDATORY_FIELDS_MISSING, exception.getErrorCode());
        Assert.assertTrue(exception.getMessage().contains("signatureAlgo"));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * An ldp_vc configuration created in VCIssuance mode can hold no signature_algo, as the insurance
     * setup does. It is updated without one.
     */
    @Test
    public void should_acceptUpdate_when_storedSignatureAlgoIsNullInVcIssuanceMode() {
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "VCIssuance");
        CredentialConfig stored = storedLdpVcEntity();
        stored.setSignatureAlgo(null);
        CredentialConfigurationDTO merged = ldpVcConfig();
        merged.setSignatureAlgo(null);
        when(credentialConfigRepository.findByCredentialConfigKeyId("test-credential")).thenReturn(Optional.of(stored));
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(merged);
        doNothing().when(credentialConfigMapper).updateEntityFromDto(any(CredentialConfigurationDTO.class), any(CredentialConfig.class));
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(stored);
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setSignatureAlgo(null);

        credentialConfigurationService.updateCredentialConfiguration("test-credential", request);

        Assert.assertNull(stored.getSignatureAlgo());
        Assert.assertEquals(List.of("Ed25519Signature2020"), stored.getCredentialSigningAlgValuesSupported());
        verify(credentialConfigRepository).save(stored);
    }

    @Test
    public void should_rejectUpdateAndSaveNothing_when_signatureAlgoIsMissing() {
        CredentialConfig stored = storedLdpVcEntity();
        CredentialConfigurationDTO merged = ldpVcConfig();
        merged.setSignatureAlgo(null);
        when(credentialConfigRepository.findByCredentialConfigKeyId("test-credential")).thenReturn(Optional.of(stored));
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(merged);
        doNothing().when(credentialConfigMapper).updateEntityFromDto(any(CredentialConfigurationDTO.class), any(CredentialConfig.class));
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setSignatureAlgo(null);

        CertifyException exception = assertThrows(CertifyException.class,
                () -> credentialConfigurationService.updateCredentialConfiguration("test-credential", request));

        Assert.assertEquals(ErrorConstants.LDP_VC_MANDATORY_FIELDS_MISSING, exception.getErrorCode());
        Assert.assertEquals(storedLdpVcEntity().getCredentialSigningAlgValuesSupported(), stored.getCredentialSigningAlgValuesSupported());
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    // ---------- A proof type has to name its proof signing algorithms ----------

    @Test
    public void should_rejectAdd_when_proofTypeHasNoAlgorithmList() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setProofTypesSupported(Map.of("jwt", Map.of()));

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        assertRejectedAsInvalidRequestNaming(exception, PROOF_SIGNING_ALGS);
        Assert.assertTrue(exception.getErrors().getFirst().getErrorMessage().contains("jwt"));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    @Test
    public void should_rejectAdd_when_proofTypeIsNull() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        LinkedHashMap<String, Object> proofTypes = new LinkedHashMap<>();
        proofTypes.put("jwt", null);
        request.setProofTypesSupported(proofTypes);

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        assertRejectedAsInvalidRequestNaming(exception, PROOF_SIGNING_ALGS);
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    @Test
    public void should_rejectAdd_when_proofTypeHasEmptyAlgorithmList() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setProofTypesSupported(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of())));

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        assertRejectedAsInvalidRequestNaming(exception, PROOF_SIGNING_ALGS);
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    // ---------- What is accepted is stored exactly as requested ----------

    /**
     * Each value narrows what the deployment declares, and nothing is added back from it: the proof type
     * keeps the one algorithm requested rather than the four declared. The signing algorithm stored is
     * the configuration's signatureAlgo.
     */
    @Test
    public void should_storeExactlyTheRequestedValues_when_allThreeAreDeclared() {
        CredentialConfig entity = ldpVcEntity();
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);

        credentialConfigurationService.addCredentialConfiguration(ldpVcRequest());

        Assert.assertEquals(List.of("did:jwk"), entity.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(List.of("Ed25519Signature2020"), entity.getCredentialSigningAlgValuesSupported());
        Assert.assertEquals(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA"))), entity.getProofTypesSupported());
    }

    /**
     * A value listed more than once is accepted and stored once, keeping the order it was first given in.
     */
    @Test
    public void should_storeEachValueOnce_when_addRepeatsValues() {
        CredentialConfig entity = ldpVcEntity();
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setCryptographicBindingMethodsSupported(List.of("did:web", "did:jwk", "did:web"));
        request.setProofTypesSupported(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("ES256", "EdDSA", "ES256"))));

        credentialConfigurationService.addCredentialConfiguration(request);

        Assert.assertEquals(List.of("did:web", "did:jwk"), entity.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(List.of("Ed25519Signature2020"), entity.getCredentialSigningAlgValuesSupported());
        Assert.assertEquals(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("ES256", "EdDSA"))), entity.getProofTypesSupported());
    }

    /**
     * Duplicates are removed before validation, so an undeclared value given twice is reported once.
     */
    @Test
    public void should_reportUndeclaredValueOnce_when_itIsRepeated() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setCryptographicBindingMethodsSupported(List.of("cose_key", "cose_key"));

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(1, exception.getErrors().size());
        Assert.assertEquals(ErrorConstants.UNSUPPORTED_CRYPTOGRAPHIC_BINDING_METHOD,
                exception.getErrors().getFirst().getErrorCode());
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * With no crypto suite the allow-list is the key selection configuration.
     */
    @Test
    public void should_acceptSdJwt_when_algorithmHasASigningKey() {
        CredentialConfig entity = sdJwtEntity();
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);

        credentialConfigurationService.addCredentialConfiguration(sdJwtRequest());

        Assert.assertEquals(List.of("ES256"), entity.getCredentialSigningAlgValuesSupported());
    }

    @Test
    public void should_acceptMsoMdoc_when_valuesAreDeclared() {
        CredentialConfig entity = msoMdocEntity();
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);

        credentialConfigurationService.addCredentialConfiguration(msoMdocRequest());

        Assert.assertEquals(List.of("cose_key"), entity.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(List.of("ES256"), entity.getCredentialSigningAlgValuesSupported());
    }

    // ---------- Undeclared values are rejected and nothing is saved ----------

    @Test
    public void should_rejectAdd_when_bindingMethodIsUndeclared() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setCryptographicBindingMethodsSupported(List.of("cose_key"));

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(ErrorConstants.UNSUPPORTED_CRYPTOGRAPHIC_BINDING_METHOD,
                exception.getErrors().getFirst().getErrorCode());
        Assert.assertTrue(exception.getErrors().getFirst().getErrorMessage().contains("cose_key"));
        Assert.assertTrue(exception.getErrors().getFirst().getErrorMessage().contains("did:jwk"));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * A format the deployment declares no binding methods for.
     */
    @Test
    public void should_rejectAdd_when_formatDeclaresNoBindingMethods() {
        ReflectionTestUtils.setField(credentialConfigurationService, "cryptographicBindingMethodsSupportedMap",
                new LinkedHashMap<String, List<String>>());
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(ldpVcRequest()));

        Assert.assertEquals(ErrorConstants.CRYPTOGRAPHIC_BINDING_CONFIG_NOT_FOUND,
                exception.getErrors().getFirst().getErrorCode());
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * signatureAlgo is optional in VCIssuance mode, but a value that is sent is validated as in
     * DataProvider mode: the VCIssuance plugin skips only the key selection check.
     */
    @Test
    public void should_rejectAdd_when_algorithmIsNotDeclaredForCryptoSuiteInVcIssuanceMode() {
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "VCIssuance");
        CredentialConfig entity = ldpVcEntity();
        entity.setSignatureAlgo("RS256");
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setSignatureAlgo("RS256");

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(ErrorConstants.UNSUPPORTED_SIGNATURE_ALGO,
                exception.getErrors().getFirst().getErrorCode());
        Assert.assertTrue(exception.getErrors().getFirst().getErrorMessage().contains("Ed25519Signature2020"));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    @Test
    public void should_rejectMsoMdoc_when_algorithmHasNoSigningKeyInVcIssuanceMode() {
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "VCIssuance");
        ReflectionTestUtils.setField(credentialConfigurationService, "keyAliasMapper", Map.of());
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(msoMdocEntity());

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(msoMdocRequest()));

        Assert.assertEquals(ErrorConstants.KEY_CHOOSER_CONFIG_NOT_FOUND,
                exception.getErrors().getFirst().getErrorCode());
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    @Test
    public void should_rejectSdJwt_when_algorithmHasNoSigningKeyInVcIssuanceMode() {
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "VCIssuance");
        CredentialConfig entity = sdJwtEntity();
        entity.setSignatureAlgo("PS256");
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        CredentialConfigurationDTO request = sdJwtRequest();
        request.setSignatureAlgo("PS256");

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(ErrorConstants.KEY_CHOOSER_CONFIG_NOT_FOUND,
                exception.getErrors().getFirst().getErrorCode());
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * An mso_mdoc configuration advertises its signatureAlgo as a COSE identifier in either mode, so the
     * COSE rule still applies in VCIssuance mode.
     */
    @Test
    public void should_rejectMsoMdoc_when_algorithmHasNoCoseEquivalentInVcIssuanceMode() {
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "VCIssuance");
        ReflectionTestUtils.setField(credentialConfigurationService, "keyAliasMapper",
                Map.of("PS256", List.of(List.of("TEST_EC", "TEST_EC-REF"))));
        CredentialConfig entity = msoMdocEntity();
        entity.setSignatureAlgo("PS256");
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        CredentialConfigurationDTO request = msoMdocRequest();
        request.setSignatureAlgo("PS256");

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(ErrorConstants.UNSUPPORTED_CREDENTIAL_SIGNING_ALG,
                exception.getErrors().getFirst().getErrorCode());
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * An algorithm the deployment holds no signing key for.
     */
    @Test
    public void should_rejectSdJwt_when_algorithmHasNoSigningKey() {
        CredentialConfig entity = sdJwtEntity();
        entity.setSignatureAlgo("PS256");
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        CredentialConfigurationDTO request = sdJwtRequest();
        request.setSignatureAlgo("PS256");

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(ErrorConstants.KEY_CHOOSER_CONFIG_NOT_FOUND,
                exception.getErrors().getFirst().getErrorCode());
        Assert.assertTrue(exception.getErrors().getFirst().getErrorMessage().contains("PS256"));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * An mso_mdoc credential is advertised with COSE algorithm identifiers, so an algorithm the
     * deployment holds a signing key for but that has no COSE equivalent is rejected on write instead of
     * failing when the issuer metadata is built.
     */
    @Test
    public void should_rejectMsoMdoc_when_algorithmHasNoCoseEquivalent() {
        ReflectionTestUtils.setField(credentialConfigurationService, "keyAliasMapper",
                Map.of("PS256", List.of(List.of("TEST_EC", "TEST_EC-REF"))));
        CredentialConfig entity = msoMdocEntity();
        entity.setSignatureAlgo("PS256");
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        CredentialConfigurationDTO request = msoMdocRequest();
        request.setSignatureAlgo("PS256");

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(ErrorConstants.UNSUPPORTED_CREDENTIAL_SIGNING_ALG,
                exception.getErrors().getFirst().getErrorCode());
        // PS256 is named, and the reason is that mso_mdoc does not support it, not a missing COSE identifier.
        Assert.assertTrue(exception.getErrors().getFirst().getErrorMessage()
                .contains("PS256 is not supported for the credential format mso_mdoc"));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * Only ES256 is supported for an mdoc's issuerAuth. EdDSA, RS256 and ES256K have COSE identifiers,
     * but an mso_mdoc configuration may not use them.
     */
    @Test
    public void should_rejectConfiguration_when_msoMdocAlgorithmIsUnsupported() {
        Map<String, List<List<String>>> keyAliasMapper = new HashMap<>();
        for (String alg : List.of("ES256", "EdDSA", "RS256", "ES256K")) {
            keyAliasMapper.put(alg, List.of(List.of("TEST_EC", "TEST_EC-REF")));
        }
        ReflectionTestUtils.setField(credentialConfigurationService, "keyAliasMapper", keyAliasMapper);

        for (String alg : List.of("EdDSA", "RS256", "ES256K")) {
            CredentialConfig entity = msoMdocEntity();
            entity.setSignatureAlgo(alg);
            when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
            CredentialConfigurationDTO request = msoMdocRequest();
            request.setSignatureAlgo(alg);

            CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                    () -> credentialConfigurationService.addCredentialConfiguration(request));

            Assert.assertEquals(ErrorConstants.UNSUPPORTED_CREDENTIAL_SIGNING_ALG,
                    exception.getErrors().getFirst().getErrorCode());
            Assert.assertTrue(exception.getErrors().getFirst().getErrorMessage().contains(alg));
        }
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * The COSE restriction applies to mso_mdoc alone; every other format keeps the crypto suite's own
     * declared algorithms.
     */
    @Test
    public void should_acceptAlgorithmWithoutCoseEquivalent_when_formatIsNotMsoMdoc() {
        LinkedHashMap<String, List<String>> signingAlgs = new LinkedHashMap<>();
        signingAlgs.put("Ed25519Signature2020", List.of("EdDSA", "PS256"));
        declareSigningAlgs(signingAlgs);
        ReflectionTestUtils.setField(credentialConfigurationService, "keyAliasMapper",
                Map.of("PS256", List.of(List.of("TEST2019", "TEST2019-REF"))));
        CredentialConfig entity = ldpVcEntity();
        entity.setSignatureAlgo("PS256");
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setSignatureAlgo("PS256");

        credentialConfigurationService.addCredentialConfiguration(request);

        // The COSE restriction did not apply, so PS256 is accepted; ldp_vc advertises its crypto suite.
        Assert.assertEquals("PS256", entity.getSignatureAlgo());
        Assert.assertEquals(List.of("Ed25519Signature2020"), entity.getCredentialSigningAlgValuesSupported());
    }

    private void declareSigningAlgs(Map<String, List<String>> byCryptoSuite) {
        ReflectionTestUtils.setField(credentialConfigurationService, "credentialSigningAlgValuesSupportedMap",
                new LinkedHashMap<>(byCryptoSuite));
    }

    // ---------- dc+sd-jwt and mso_mdoc are checked against the key selection configuration only ----------

    /**
     * credential-signing-alg-values-supported is keyed by ldp_vc crypto suite and plays no part for
     * dc+sd-jwt or mso_mdoc: with nothing declared in it, an algorithm with a signing key is accepted.
     */
    @Test
    public void should_validateAgainstKeyAliasMapperOnly_when_formatIsSdJwtOrMsoMdoc() {
        declareSigningAlgs(new LinkedHashMap<>());
        CredentialConfig sdJwt = sdJwtEntity();
        CredentialConfig msoMdoc = msoMdocEntity();
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(sdJwt, msoMdoc);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenAnswer(invocation -> invocation.getArgument(0));

        credentialConfigurationService.addCredentialConfiguration(sdJwtRequest());
        credentialConfigurationService.addCredentialConfiguration(msoMdocRequest());

        Assert.assertEquals(List.of("ES256"), sdJwt.getCredentialSigningAlgValuesSupported());
        Assert.assertEquals(List.of("ES256"), msoMdoc.getCredentialSigningAlgValuesSupported());
    }

    @Test
    public void should_rejectMsoMdocWithKeyChooserConfigNotFound_when_algorithmHasNoSigningKey() {
        ReflectionTestUtils.setField(credentialConfigurationService, "keyAliasMapper",
                Map.of("EdDSA", List.of(List.of("TEST2019", "TEST2019-REF"))));
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(msoMdocEntity());

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(msoMdocRequest()));

        Assert.assertEquals(ErrorConstants.KEY_CHOOSER_CONFIG_NOT_FOUND, exception.getErrors().getFirst().getErrorCode());
        Assert.assertTrue(exception.getErrors().getFirst().getErrorMessage().contains("ES256"));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * An algorithm with no signing key is reported once, not a second time by the COSE check.
     */
    @Test
    public void should_reportOneError_when_msoMdocAlgorithmHasNeitherSigningKeyNorCose() {
        CredentialConfig entity = msoMdocEntity();
        entity.setSignatureAlgo("ES25");
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        CredentialConfigurationDTO request = msoMdocRequest();
        request.setSignatureAlgo("ES25");

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(1, exception.getErrors().size());
        Assert.assertEquals(ErrorConstants.KEY_CHOOSER_CONFIG_NOT_FOUND, exception.getErrors().getFirst().getErrorCode());
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    @Test
    public void should_rejectLdpVc_when_cryptoSuiteIsNotDeclared() {
        declareSigningAlgs(new LinkedHashMap<>());

        CertifyException exception = assertThrows(CertifyException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(ldpVcRequest()));

        Assert.assertEquals(ErrorConstants.UNSUPPORTED_CRYPTO_SUITE, exception.getErrorCode());
        Assert.assertEquals("Unsupported signature crypto suite: Ed25519Signature2020", exception.getMessage());
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * In VCIssuance mode the key-alias check is skipped, and the metadata validator reports the
     * unsupported crypto suite the same way.
     */
    @Test
    public void should_rejectLdpVc_when_cryptoSuiteIsNotDeclaredInVcIssuanceMode() {
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "VCIssuance");
        declareSigningAlgs(new LinkedHashMap<>());
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(ldpVcRequest()));

        Assert.assertEquals(ErrorConstants.UNSUPPORTED_CRYPTO_SUITE, exception.getErrors().getFirst().getErrorCode());
        Assert.assertEquals("Unsupported signature crypto suite: Ed25519Signature2020",
                exception.getErrors().getFirst().getErrorMessage());
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    @Test
    public void should_rejectAdd_when_proofTypeIsUndeclared() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setProofTypesSupported(Map.of("ldp_vp", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA"))));

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(ErrorConstants.UNSUPPORTED_PROOF_TYPE, exception.getErrors().getFirst().getErrorCode());
        Assert.assertTrue(exception.getErrors().getFirst().getErrorMessage().contains("jwt"));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    @Test
    public void should_rejectAdd_when_proofSigningAlgorithmIsUndeclared() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setProofTypesSupported(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("ES512"))));

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(ErrorConstants.UNSUPPORTED_PROOF_SIGNING_ALG,
                exception.getErrors().getFirst().getErrorCode());
        Assert.assertTrue(exception.getErrors().getFirst().getErrorMessage().contains("ES512"));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * An attribute the deployment does not recognise inside a proof type entry.
     */
    @Test
    public void should_rejectAdd_when_proofTypeHasUnrecognisedAttribute() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setProofTypesSupported(Map.of("jwt", Map.of(
                PROOF_SIGNING_ALGS, List.of("EdDSA"),
                "unknown_attribute", List.of("EdDSA"))));

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        assertRejectedAsInvalidRequestNaming(exception, "unknown_attribute");
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    @Test
    public void should_reportAllErrorsTogether_when_severalValuesAreInvalid() {
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "VCIssuance");
        CredentialConfig entity = ldpVcEntity();
        entity.setSignatureAlgo("RS256");
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setSignatureAlgo("RS256");
        request.setCryptographicBindingMethodsSupported(List.of("cose_key"));
        request.setProofTypesSupported(Map.of("ldp_vp", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA"))));

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        List<String> errorCodes = exception.getErrors().stream().map(io.mosip.certify.core.dto.Error::getErrorCode).toList();
        Assert.assertEquals(3, errorCodes.size());
        Assert.assertTrue(errorCodes.contains(ErrorConstants.UNSUPPORTED_CRYPTOGRAPHIC_BINDING_METHOD));
        Assert.assertTrue(errorCodes.contains(ErrorConstants.UNSUPPORTED_SIGNATURE_ALGO));
        Assert.assertTrue(errorCodes.contains(ErrorConstants.UNSUPPORTED_PROOF_TYPE));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    // ---------- A proof type declared with no proof signing algorithms ----------

    /**
     * The deployment may declare a proof type with no proof signing algorithms. That is no longer filled
     * in on write, so it cannot break a request that does not name it.
     */
    @Test
    public void should_acceptAdd_when_proofTypeDeclaredWithoutSigningAlgsIsNotNamed() {
        LinkedHashMap<String, Object> proofTypes = new LinkedHashMap<>();
        proofTypes.put("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA")));
        proofTypes.put("ldp_vp", Map.of(PROOF_SIGNING_ALGS, List.of()));
        ReflectionTestUtils.setField(credentialConfigurationService, "proofTypesSupported", proofTypes);
        CredentialConfig entity = ldpVcEntity();
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);

        credentialConfigurationService.addCredentialConfiguration(ldpVcRequest());

        Assert.assertEquals(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA"))), entity.getProofTypesSupported());
    }

    /**
     * Only a request naming that proof type is rejected, since no algorithm it names can be declared.
     */
    @Test
    public void should_rejectAdd_when_proofTypeDeclaredWithoutSigningAlgsIsNamed() {
        LinkedHashMap<String, Object> proofTypes = new LinkedHashMap<>();
        proofTypes.put("jwt", Map.of(PROOF_SIGNING_ALGS, List.of()));
        ReflectionTestUtils.setField(credentialConfigurationService, "proofTypesSupported", proofTypes);
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(ldpVcRequest()));

        Assert.assertEquals(ErrorConstants.UNSUPPORTED_PROOF_SIGNING_ALG,
                exception.getErrors().getFirst().getErrorCode());
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    // ---------- Update: both attributes are mandatory and replace what is stored ----------

    @Test
    public void should_replaceStoredValues_when_updateSendsAllThree() {
        CredentialConfig stored = storedLdpVcEntity();
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setCryptographicBindingMethodsSupported(List.of("did:web"));
        stubUpdateOf(stored);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(stored);

        credentialConfigurationService.updateCredentialConfiguration("test-credential", request);

        Assert.assertEquals(List.of("did:web"), stored.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(List.of("Ed25519Signature2020"), stored.getCredentialSigningAlgValuesSupported());
        Assert.assertEquals(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA"))), stored.getProofTypesSupported());
    }

    /**
     * An attribute left out of an update is rejected rather than retained or re-derived, and what is
     * stored is left untouched.
     */
    @Test
    public void should_rejectUpdateAndSaveNothing_when_anyAttributeIsMissingOrNull() {
        CredentialConfig stored = storedLdpVcEntity();
        stubUpdateOf(stored);

        CLEAR_ATTRIBUTE.forEach((attribute, clear) -> {
            CredentialConfigurationDTO request = ldpVcRequest();
            clear.accept(request);

            CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                    () -> credentialConfigurationService.updateCredentialConfiguration("test-credential", request));

            assertRejectedAsInvalidRequestNaming(exception, attribute);
        });
        Assert.assertEquals(storedLdpVcEntity().getCryptographicBindingMethodsSupported(), stored.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(storedLdpVcEntity().getCredentialSigningAlgValuesSupported(), stored.getCredentialSigningAlgValuesSupported());
        Assert.assertEquals(storedLdpVcEntity().getProofTypesSupported(), stored.getProofTypesSupported());
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    @Test
    public void should_rejectUpdateAndSaveNothing_when_anyAttributeIsEmpty() {
        stubUpdateOf(storedLdpVcEntity());

        EMPTY_ATTRIBUTE.forEach((attribute, empty) -> {
            CredentialConfigurationDTO request = ldpVcRequest();
            empty.accept(request);

            CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                    () -> credentialConfigurationService.updateCredentialConfiguration("test-credential", request));

            assertRejectedAsInvalidRequestNaming(exception, attribute);
        });
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    @Test
    public void should_rejectUpdateAndSaveNothing_when_valueIsUndeclared() {
        stubUpdateOf(storedLdpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setCryptographicBindingMethodsSupported(List.of("cose_key"));

        assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.updateCredentialConfiguration("test-credential", request));

        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    @Test
    public void should_storeEachValueOnce_when_updateRepeatsValues() {
        CredentialConfig stored = storedLdpVcEntity();
        stubUpdateOf(stored);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(stored);
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setCryptographicBindingMethodsSupported(List.of("did:jwk", "did:jwk"));
        request.setProofTypesSupported(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA", "EdDSA"))));

        credentialConfigurationService.updateCredentialConfiguration("test-credential", request);

        Assert.assertEquals(List.of("did:jwk"), stored.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA"))), stored.getProofTypesSupported());
    }

    /**
     * A configuration created before these attributes were stored is updated like any other: what it is
     * left holding is exactly what the request sent, with the crypto suite name it stored replaced by its
     * signatureAlgo.
     */
    @Test
    public void should_storeExactlyTheRequestedValues_when_legacyConfigurationIsUpdated() {
        CredentialConfig legacy = ldpVcEntity();
        legacy.setCredentialSigningAlgValuesSupported(List.of("Ed25519Signature2020"));
        stubUpdateOf(legacy);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(legacy);

        credentialConfigurationService.updateCredentialConfiguration("test-credential", ldpVcRequest());

        Assert.assertEquals(List.of("did:jwk"), legacy.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(List.of("Ed25519Signature2020"), legacy.getCredentialSigningAlgValuesSupported());
        Assert.assertEquals(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA"))), legacy.getProofTypesSupported());
    }

    // ---------- The Get response always carries both, and the signing algorithm as signatureAlgo ----------

    @Test
    public void should_returnStoredValues_when_configurationIsFetched() {
        CredentialConfig stored = ldpVcEntity();
        stored.setCryptographicBindingMethodsSupported(List.of("did:web"));
        stored.setCredentialSigningAlgValuesSupported(List.of("EdDSA"));
        stored.setProofTypesSupported(new LinkedHashMap<>(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA")))));

        CredentialConfigurationDTO mapped = ldpVcConfig();
        mapped.setCryptographicBindingMethodsSupported(stored.getCryptographicBindingMethodsSupported());
        mapped.setProofTypesSupported(stored.getProofTypesSupported());

        when(credentialConfigRepository.findByCredentialConfigKeyId("test-credential")).thenReturn(Optional.of(stored));
        when(credentialConfigMapper.toDto(stored)).thenReturn(mapped);

        CredentialConfigurationDTO result = credentialConfigurationService.getCredentialConfigurationById("test-credential");

        Assert.assertEquals(List.of("did:web"), result.getCryptographicBindingMethodsSupported());
        Assert.assertEquals("EdDSA", result.getSignatureAlgo());
        Assert.assertEquals(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA"))), result.getProofTypesSupported());
    }

    /**
     * A configuration created before these attributes were stored keeps returning what it always has:
     * the declared defaults for the binding methods and proof types.
     */
    @Test
    public void should_returnResolvedDefaults_when_legacyConfigurationIsFetched() {
        CredentialConfig legacy = ldpVcEntity();
        legacy.setCredentialSigningAlgValuesSupported(List.of("Ed25519Signature2020"));

        when(credentialConfigRepository.findByCredentialConfigKeyId("test-credential")).thenReturn(Optional.of(legacy));
        when(credentialConfigMapper.toDto(legacy)).thenReturn(ldpVcConfig());

        CredentialConfigurationDTO result = credentialConfigurationService.getCredentialConfigurationById("test-credential");

        Assert.assertEquals(List.of("did:jwk", "did:web"), result.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(Set.of("jwt"), result.getProofTypesSupported().keySet());
    }

    // ---------- The credential issuer metadata ----------

    @Test
    public void should_advertiseStoredValues_when_metadataIsBuilt() {
        CredentialConfig stored = ldpVcEntity();
        stored.setCryptographicBindingMethodsSupported(List.of("did:web"));
        stored.setCredentialSigningAlgValuesSupported(List.of("EdDSA"));
        stored.setProofTypesSupported(new LinkedHashMap<>(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA")))));

        when(credentialConfigRepository.findAll()).thenReturn(List.of(stored));
        when(credentialConfigMapper.toDto(stored)).thenReturn(ldpVcConfig());

        CredentialIssuerMetadataDTO metadata = credentialConfigurationService.fetchCredentialIssuerMetadata();

        CredentialConfigurationSupportedDTO supported =
                metadata.getCredentialConfigurationSupportedDTO().get("test-credential");
        Assert.assertEquals(List.of("Ed25519Signature2020"), supported.getCredentialSigningAlgValuesSupported());
        Assert.assertEquals(List.of("did:web"), supported.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA"))), supported.getProofTypesSupported());
    }

    /**
     * An ldp_vc configuration advertises the crypto suite it signs with, per OpenID4VCI 1.0 Appendix
     * A.1.2.2, whatever list is stored against it, so a wallet is never told of something the credential
     * is not signed with.
     */
    @Test
    public void should_advertiseCryptoSuite_when_ldpVcStoredListDiffers() {
        CredentialConfig stored = storedLdpVcEntity();
        stored.setCredentialSigningAlgValuesSupported(List.of("RS256", "EdDSA"));

        when(credentialConfigRepository.findAll()).thenReturn(List.of(stored));
        when(credentialConfigMapper.toDto(stored)).thenReturn(ldpVcConfig());

        CredentialIssuerMetadataDTO metadata = credentialConfigurationService.fetchCredentialIssuerMetadata();

        Assert.assertEquals(List.of("Ed25519Signature2020"),
                metadata.getCredentialConfigurationSupportedDTO().get("test-credential").getCredentialSigningAlgValuesSupported());
    }

    /**
     * Every Data Integrity crypto suite Certify signs ldp_vc with is advertised by its own name, per
     * OpenID4VCI 1.0 Appendix A.1.2.2, rather than by the JWS algorithm behind it, which several suites
     * share.
     */
    @Test
    public void should_advertiseItsCryptoSuite_when_ldpVcIsSignedWithEachSupportedSuite() {
        Map<String, String> algorithmBySuite = new LinkedHashMap<>();
        algorithmBySuite.put("RsaSignature2018", "RS256");
        algorithmBySuite.put("Ed25519Signature2018", "EdDSA");
        algorithmBySuite.put("Ed25519Signature2020", "EdDSA");
        algorithmBySuite.put("EcdsaKoblitzSignature2016", "ES256K");
        algorithmBySuite.put("EcdsaSecp256k1Signature2019", "ES256K");
        algorithmBySuite.put("EcdsaSecp256r1Signature2019", "ES256");
        algorithmBySuite.put("ecdsa-rdfc-2019", "ES256");
        algorithmBySuite.put("ecdsa-jcs-2019", "ES256");
        algorithmBySuite.put("eddsa-rdfc-2022", "EdDSA");
        algorithmBySuite.put("eddsa-jcs-2022", "EdDSA");

        List<CredentialConfig> configs = new ArrayList<>();
        algorithmBySuite.forEach((suite, algorithm) -> {
            CredentialConfig config = storedLdpVcEntity();
            config.setCredentialConfigKeyId(suite);
            config.setSignatureCryptoSuite(suite);
            config.setSignatureAlgo(algorithm);
            config.setCredentialSigningAlgValuesSupported(List.of(algorithm));
            configs.add(config);
            when(credentialConfigMapper.toDto(config)).thenReturn(ldpVcConfig());
        });
        when(credentialConfigRepository.findAll()).thenReturn(configs);

        Map<String, CredentialConfigurationSupportedDTO> supported =
                credentialConfigurationService.fetchCredentialIssuerMetadata().getCredentialConfigurationSupportedDTO();

        Assert.assertEquals(algorithmBySuite.keySet(), supported.keySet());
        algorithmBySuite.keySet().forEach(suite ->
                Assert.assertEquals(List.of(suite), supported.get(suite).getCredentialSigningAlgValuesSupported()));
    }

    /**
     * Every format other than ldp_vc advertises its signatureAlgo as a single-valued list; mso_mdoc
     * carries it as its COSE algorithm identifier.
     */
    @Test
    public void should_advertiseSignatureAlgo_when_formatIsSdJwtOrMsoMdoc() {
        CredentialConfig sdJwt = sdJwtEntity();
        sdJwt.setCredentialSigningAlgValuesSupported(List.of("ES256"));
        CredentialConfig msoMdoc = msoMdocEntity();
        msoMdoc.setCredentialSigningAlgValuesSupported(List.of("ES256"));

        when(credentialConfigRepository.findAll()).thenReturn(List.of(sdJwt, msoMdoc));
        when(credentialConfigMapper.toDto(sdJwt)).thenReturn(sdJwtConfig());
        when(credentialConfigMapper.toDto(msoMdoc)).thenReturn(msoMdocConfig());

        Map<String, CredentialConfigurationSupportedDTO> supported =
                credentialConfigurationService.fetchCredentialIssuerMetadata().getCredentialConfigurationSupportedDTO();

        Assert.assertEquals(List.of("ES256"), supported.get("test-sd-jwt").getCredentialSigningAlgValuesSupported());
        Assert.assertEquals(List.of(-7), supported.get("test-mso-mdoc").getCredentialSigningAlgValuesSupported());
    }

    /**
     * An ldp_vc configuration created in VCIssuance mode without a signatureAlgo still advertises its
     * crypto suite.
     */
    @Test
    public void should_advertiseCryptoSuite_when_ldpVcConfigurationHasNoSignatureAlgo() {
        CredentialConfig ldpVc = ldpVcEntity();
        ldpVc.setSignatureAlgo(null);
        ldpVc.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        ldpVc.setCredentialSigningAlgValuesSupported(List.of("Ed25519Signature2020"));

        when(credentialConfigRepository.findAll()).thenReturn(List.of(ldpVc));
        when(credentialConfigMapper.toDto(ldpVc)).thenReturn(ldpVcConfig());

        CredentialConfigurationSupportedDTO supported = credentialConfigurationService.fetchCredentialIssuerMetadata()
                .getCredentialConfigurationSupportedDTO().get("test-credential");

        Assert.assertEquals(List.of("Ed25519Signature2020"), supported.getCredentialSigningAlgValuesSupported());
    }

    /**
     * A dc+sd-jwt configuration created in VCIssuance mode without a signatureAlgo has no algorithm to
     * advertise, so credential_signing_alg_values_supported is left out rather than published empty.
     */
    @Test
    public void should_omitSigningAlgs_when_sdJwtConfigurationHasNoSignatureAlgo() {
        CredentialConfig sdJwt = sdJwtEntity();
        sdJwt.setSignatureAlgo(null);
        sdJwt.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        sdJwt.setCredentialSigningAlgValuesSupported(List.of());

        when(credentialConfigRepository.findAll()).thenReturn(List.of(sdJwt));
        when(credentialConfigMapper.toDto(sdJwt)).thenReturn(sdJwtConfig());

        CredentialConfigurationSupportedDTO supported = credentialConfigurationService.fetchCredentialIssuerMetadata()
                .getCredentialConfigurationSupportedDTO().get("test-sd-jwt");

        Assert.assertNotNull(supported);
        Assert.assertNull(supported.getCredentialSigningAlgValuesSupported());
    }

    /**
     * An mso_mdoc configuration created in VCIssuance mode without a signatureAlgo has no algorithm to
     * advertise, so credential_signing_alg_values_supported is left out rather than published empty.
     */
    @Test
    public void should_omitSigningAlgs_when_msoMdocConfigurationHasNoSignatureAlgo() {
        CredentialConfig msoMdoc = msoMdocEntity();
        msoMdoc.setSignatureAlgo(null);
        msoMdoc.setCryptographicBindingMethodsSupported(List.of("cose_key"));
        msoMdoc.setCredentialSigningAlgValuesSupported(List.of());

        when(credentialConfigRepository.findAll()).thenReturn(List.of(msoMdoc));
        when(credentialConfigMapper.toDto(msoMdoc)).thenReturn(msoMdocConfig());

        CredentialConfigurationSupportedDTO supported = credentialConfigurationService.fetchCredentialIssuerMetadata()
                .getCredentialConfigurationSupportedDTO().get("test-mso-mdoc");

        Assert.assertNotNull(supported);
        Assert.assertNull(supported.getCredentialSigningAlgValuesSupported());
    }

    /**
     * A legacy ldp_vc configuration, with no signatureAlgo and its crypto suite name stored, now
     * advertises that crypto suite rather than the algorithm it used to be resolved to.
     */
    @Test
    public void should_advertiseCryptoSuite_when_ldpVcConfigurationIsLegacy() {
        CredentialConfig legacy = ldpVcEntity();
        legacy.setSignatureAlgo(null);
        legacy.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        legacy.setCredentialSigningAlgValuesSupported(List.of("Ed25519Signature2020"));

        when(credentialConfigRepository.findAll()).thenReturn(List.of(legacy));
        when(credentialConfigMapper.toDto(legacy)).thenReturn(ldpVcConfig());

        CredentialIssuerMetadataDTO metadata = credentialConfigurationService.fetchCredentialIssuerMetadata();

        CredentialConfigurationSupportedDTO supported =
                metadata.getCredentialConfigurationSupportedDTO().get("test-credential");
        Assert.assertEquals(List.of("Ed25519Signature2020"), supported.getCredentialSigningAlgValuesSupported());
        Assert.assertEquals(List.of("did:jwk"), supported.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(Set.of("jwt"), supported.getProofTypesSupported().keySet());
    }

    /**
     * A legacy mso_mdoc configuration stored a crypto suite and its name in place of the signing
     * algorithms. It advertises its own signatureAlgo, as a COSE identifier, without being re-submitted
     * and with nothing resolved from the deployment configuration.
     */
    @Test
    public void should_advertiseSignatureAlgo_when_msoMdocConfigurationIsLegacy() {
        declareSigningAlgs(new LinkedHashMap<>());
        CredentialConfig legacy = msoMdocEntity();
        legacy.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        legacy.setCredentialSigningAlgValuesSupported(List.of("EcdsaSecp256r1Signature2019"));

        when(credentialConfigRepository.findAll()).thenReturn(List.of(legacy));
        when(credentialConfigMapper.toDto(legacy)).thenReturn(msoMdocConfig());

        CredentialIssuerMetadataDTO metadata = credentialConfigurationService.fetchCredentialIssuerMetadata();

        Assert.assertEquals(List.of(-7),
                metadata.getCredentialConfigurationSupportedDTO().get("test-mso-mdoc").getCredentialSigningAlgValuesSupported());
    }

    /**
     * A legacy stored proof type carrying no algorithm list is advertised with the algorithms declared for
     * it, so the published metadata stays valid under OpenID4VCI.
     */
    @Test
    public void should_advertiseDeclaredAlgorithms_when_legacyProofTypeHasNoAlgorithmList() {
        CredentialConfig legacy = ldpVcEntity();
        legacy.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        legacy.setCredentialSigningAlgValuesSupported(List.of("EdDSA"));
        LinkedHashMap<String, Object> bare = new LinkedHashMap<>();
        bare.put("jwt", Map.of());
        legacy.setProofTypesSupported(bare);

        when(credentialConfigRepository.findAll()).thenReturn(List.of(legacy));
        when(credentialConfigMapper.toDto(legacy)).thenReturn(ldpVcConfig());

        CredentialIssuerMetadataDTO metadata = credentialConfigurationService.fetchCredentialIssuerMetadata();

        Assert.assertEquals(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("RS256", "PS256", "ES256", "EdDSA"))),
                metadata.getCredentialConfigurationSupportedDTO().get("test-credential").getProofTypesSupported());
    }

    /**
     * Writes reject an mso_mdoc algorithm with no COSE equivalent, so a legacy row stored with one has to
     * be corrected. It is left out of the metadata rather than advertised with something the format
     * cannot carry, and every other configuration is still served.
     */
    @Test
    public void should_omitOnlyInvalidConfiguration_when_legacyMsoMdocAlgorithmIsUnmappable() {
        CredentialConfig legacy = msoMdocEntity();
        legacy.setSignatureAlgo("PS256");
        CredentialConfig healthy = ldpVcEntity();
        healthy.setCredentialSigningAlgValuesSupported(List.of("EdDSA"));

        when(credentialConfigRepository.findAll()).thenReturn(List.of(legacy, healthy));
        when(credentialConfigMapper.toDto(legacy)).thenReturn(msoMdocConfig());
        when(credentialConfigMapper.toDto(healthy)).thenReturn(ldpVcConfig());

        CredentialIssuerMetadataDTO metadata = credentialConfigurationService.fetchCredentialIssuerMetadata();

        Assert.assertEquals(Set.of("test-credential"), metadata.getCredentialConfigurationSupportedDTO().keySet());
    }

    /**
     * A stored proof type the deployment no longer declares any signing algorithm for cannot be advertised
     * either, and only that configuration is left out.
     */
    @Test
    public void should_omitOnlyInvalidConfiguration_when_proofTypeHasNoSigningAlgorithms() {
        LinkedHashMap<String, Object> proofTypes = new LinkedHashMap<>();
        proofTypes.put("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA")));
        proofTypes.put("ldp_vp", Map.of(PROOF_SIGNING_ALGS, List.of()));
        ReflectionTestUtils.setField(credentialConfigurationService, "proofTypesSupported", proofTypes);
        CredentialConfig broken = sdJwtEntity();
        broken.setProofTypesSupported(new LinkedHashMap<>(Map.of("ldp_vp", Map.of())));
        CredentialConfig healthy = ldpVcEntity();
        healthy.setProofTypesSupported(new LinkedHashMap<>(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA")))));

        when(credentialConfigRepository.findAll()).thenReturn(List.of(broken, healthy));
        when(credentialConfigMapper.toDto(broken)).thenReturn(sdJwtConfig());
        when(credentialConfigMapper.toDto(healthy)).thenReturn(ldpVcConfig());

        CredentialIssuerMetadataDTO metadata = credentialConfigurationService.fetchCredentialIssuerMetadata();

        Assert.assertEquals(Set.of("test-credential"), metadata.getCredentialConfigurationSupportedDTO().keySet());
    }

    /**
     * The startup check reports a configuration that cannot be advertised without stopping the service:
     * the metadata endpoint keeps serving every other configuration.
     */
    @Test
    public void should_completeStartupValidation_when_configurationCannotBeAdvertised() {
        CredentialConfig legacy = msoMdocEntity();
        legacy.setSignatureAlgo("PS256");

        when(credentialConfigRepository.findAll()).thenReturn(List.of(legacy));
        when(credentialConfigMapper.toDto(legacy)).thenReturn(msoMdocConfig());

        credentialConfigurationService.validateStoredConfigurations();

        verify(credentialConfigMapper).toDto(legacy);
    }

    /**
     * A deployment declaring a proof type with no proof signing algorithms still starts: the startup check
     * runs to completion over every stored configuration.
     */
    @Test
    public void should_completeStartupValidation_when_proofTypeIsDeclaredWithoutSigningAlgs() {
        LinkedHashMap<String, Object> proofTypes = new LinkedHashMap<>();
        proofTypes.put("jwt", Map.of(PROOF_SIGNING_ALGS, List.of()));
        ReflectionTestUtils.setField(credentialConfigurationService, "proofTypesSupported", proofTypes);
        CredentialConfig stored = storedLdpVcEntity();

        when(credentialConfigRepository.findAll()).thenReturn(List.of(stored));
        when(credentialConfigMapper.toDto(stored)).thenReturn(ldpVcConfig());

        credentialConfigurationService.validateStoredConfigurations();

        verify(credentialConfigMapper).toDto(stored);
    }
}
