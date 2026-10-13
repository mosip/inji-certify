package io.mosip.certify.services;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.CredentialConfigurationSupportedDTO;
import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.dto.MetaDataDisplayDTO;
import io.mosip.certify.core.exception.CredentialConfigValidationException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.CredentialConfigMapper;
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
 * credential_signing_alg_values_supported and proof_types_supported: all three are mandatory, what is
 * accepted is stored exactly as requested with nothing filled in from the deployment configuration,
 * what is rejected, and what reaches the Get response and the credential issuer metadata.
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
            "credentialSigningAlgValuesSupported", dto -> dto.setCredentialSigningAlgValuesSupported(null),
            "proofTypesSupported", dto -> dto.setProofTypesSupported(null));

    private static final Map<String, Consumer<CredentialConfigurationDTO>> EMPTY_ATTRIBUTE = Map.of(
            "cryptographicBindingMethodsSupported", dto -> dto.setCryptographicBindingMethodsSupported(List.of()),
            "credentialSigningAlgValuesSupported", dto -> dto.setCredentialSigningAlgValuesSupported(List.of()),
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
        ReflectionTestUtils.setField(credentialConfigurationService, "credentialSigningAlgValuesSupportedMap", signingAlgs);
        ReflectionTestUtils.setField(credentialConfigurationService, "proofTypesSupported", proofTypes);
        ReflectionTestUtils.setField(credentialConfigurationService, "keyAliasMapper", keyAliasMapper);
        ReflectionTestUtils.setField(credentialConfigurationService, "authorizationServerMapping", Map.of());
    }

    /**
     * An ldp_vc configuration without the three attributes, as the mapper returns one created before
     * they were stored.
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
     * A valid ldp_vc request, carrying all three attributes.
     */
    private CredentialConfigurationDTO ldpVcRequest() {
        CredentialConfigurationDTO dto = ldpVcConfig();
        dto.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        dto.setCredentialSigningAlgValuesSupported(List.of("EdDSA"));
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
        dto.setCredentialSigningAlgValuesSupported(List.of("ES256"));
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
        dto.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        return dto;
    }

    private CredentialConfigurationDTO msoMdocRequest() {
        CredentialConfigurationDTO dto = msoMdocConfig();
        dto.setCryptographicBindingMethodsSupported(List.of("cose_key"));
        dto.setCredentialSigningAlgValuesSupported(List.of("ES256"));
        dto.setProofTypesSupported(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("ES256"))));
        return dto;
    }

    private CredentialConfig msoMdocEntity() {
        CredentialConfig entity = new CredentialConfig();
        entity.setCredentialConfigKeyId("test-mso-mdoc");
        entity.setStatus("active");
        entity.setCredentialFormat("mso_mdoc");
        entity.setDocType("org.iso.18013.5.1.mDL");
        entity.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
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

    // ---------- All three are mandatory on add: missing, null and empty are rejected alike ----------

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
     * A request written before the attributes were mandatory sends none of them, and is told about all
     * three at once.
     */
    @Test
    public void should_reportEachAttribute_when_allThreeAreMissing() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(ldpVcConfig()));

        Assert.assertEquals(3, exception.getErrors().size());
        exception.getErrors().forEach(error ->
                Assert.assertEquals(ErrorConstants.INVALID_REQUEST, error.getErrorCode()));
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
     * keeps the one algorithm requested rather than the four declared.
     */
    @Test
    public void should_storeExactlyTheRequestedValues_when_allThreeAreDeclared() {
        CredentialConfig entity = ldpVcEntity();
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);

        credentialConfigurationService.addCredentialConfiguration(ldpVcRequest());

        Assert.assertEquals(List.of("did:jwk"), entity.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(List.of("EdDSA"), entity.getCredentialSigningAlgValuesSupported());
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
        request.setCredentialSigningAlgValuesSupported(List.of("EdDSA", "EdDSA"));
        request.setProofTypesSupported(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("ES256", "EdDSA", "ES256"))));

        credentialConfigurationService.addCredentialConfiguration(request);

        Assert.assertEquals(List.of("did:web", "did:jwk"), entity.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(List.of("EdDSA"), entity.getCredentialSigningAlgValuesSupported());
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

    @Test
    public void should_rejectAdd_when_algorithmIsNotDeclaredForCryptoSuite() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setCredentialSigningAlgValuesSupported(List.of("RS256"));

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(ErrorConstants.UNSUPPORTED_CREDENTIAL_SIGNING_ALG,
                exception.getErrors().getFirst().getErrorCode());
        Assert.assertTrue(exception.getErrors().getFirst().getErrorMessage().contains("Ed25519Signature2020"));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * An algorithm the deployment holds no signing key for.
     */
    @Test
    public void should_rejectSdJwt_when_algorithmHasNoSigningKey() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(sdJwtEntity());
        CredentialConfigurationDTO request = sdJwtRequest();
        request.setCredentialSigningAlgValuesSupported(List.of("PS256"));

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(ErrorConstants.UNSUPPORTED_CREDENTIAL_SIGNING_ALG,
                exception.getErrors().getFirst().getErrorCode());
        Assert.assertTrue(exception.getErrors().getFirst().getErrorMessage().contains("No signing key is available"));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * An mso_mdoc credential is advertised with COSE algorithm identifiers, so an algorithm the
     * deployment declares for the crypto suite but that has no COSE equivalent is rejected on write
     * instead of failing when the issuer metadata is built.
     */
    @Test
    public void should_rejectMsoMdoc_when_algorithmHasNoCoseEquivalent() {
        LinkedHashMap<String, List<String>> signingAlgs = new LinkedHashMap<>();
        signingAlgs.put("EcdsaSecp256r1Signature2019", List.of("ES256", "PS256"));
        ReflectionTestUtils.setField(credentialConfigurationService, "credentialSigningAlgValuesSupportedMap", signingAlgs);
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(msoMdocEntity());
        CredentialConfigurationDTO request = msoMdocRequest();
        request.setCredentialSigningAlgValuesSupported(List.of("PS256"));

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
        LinkedHashMap<String, List<String>> signingAlgs = new LinkedHashMap<>();
        signingAlgs.put("EcdsaSecp256r1Signature2019", List.of("ES256", "EdDSA", "RS256", "ES256K"));
        ReflectionTestUtils.setField(credentialConfigurationService, "credentialSigningAlgValuesSupportedMap", signingAlgs);
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(msoMdocEntity());

        for (String alg : List.of("EdDSA", "RS256", "ES256K")) {
            CredentialConfigurationDTO request = msoMdocRequest();
            request.setCredentialSigningAlgValuesSupported(List.of(alg));

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
        ReflectionTestUtils.setField(credentialConfigurationService, "credentialSigningAlgValuesSupportedMap", signingAlgs);
        CredentialConfig entity = ldpVcEntity();
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setCredentialSigningAlgValuesSupported(List.of("EdDSA", "PS256"));

        credentialConfigurationService.addCredentialConfiguration(request);

        Assert.assertEquals(List.of("EdDSA", "PS256"), entity.getCredentialSigningAlgValuesSupported());
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
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setCryptographicBindingMethodsSupported(List.of("cose_key"));
        request.setCredentialSigningAlgValuesSupported(List.of("RS256"));
        request.setProofTypesSupported(Map.of("ldp_vp", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA"))));

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        List<String> errorCodes = exception.getErrors().stream().map(io.mosip.certify.core.dto.Error::getErrorCode).toList();
        Assert.assertEquals(3, errorCodes.size());
        Assert.assertTrue(errorCodes.contains(ErrorConstants.UNSUPPORTED_CRYPTOGRAPHIC_BINDING_METHOD));
        Assert.assertTrue(errorCodes.contains(ErrorConstants.UNSUPPORTED_CREDENTIAL_SIGNING_ALG));
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

    // ---------- Update: all three are mandatory and replace what is stored ----------

    @Test
    public void should_replaceStoredValues_when_updateSendsAllThree() {
        CredentialConfig stored = storedLdpVcEntity();
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setCryptographicBindingMethodsSupported(List.of("did:web"));
        stubUpdateOf(stored);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(stored);

        credentialConfigurationService.updateCredentialConfiguration("test-credential", request);

        Assert.assertEquals(List.of("did:web"), stored.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(List.of("EdDSA"), stored.getCredentialSigningAlgValuesSupported());
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
     * left holding is exactly what the request sent, with the crypto suite name it stored replaced.
     */
    @Test
    public void should_storeExactlyTheRequestedValues_when_legacyConfigurationIsUpdated() {
        CredentialConfig legacy = ldpVcEntity();
        legacy.setCredentialSigningAlgValuesSupported(List.of("Ed25519Signature2020"));
        stubUpdateOf(legacy);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(legacy);

        credentialConfigurationService.updateCredentialConfiguration("test-credential", ldpVcRequest());

        Assert.assertEquals(List.of("did:jwk"), legacy.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(List.of("EdDSA"), legacy.getCredentialSigningAlgValuesSupported());
        Assert.assertEquals(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA"))), legacy.getProofTypesSupported());
    }

    // ---------- The Get response always carries all three ----------

    @Test
    public void should_returnStoredValues_when_configurationIsFetched() {
        CredentialConfig stored = ldpVcEntity();
        stored.setCryptographicBindingMethodsSupported(List.of("did:web"));
        stored.setCredentialSigningAlgValuesSupported(List.of("EdDSA"));
        stored.setProofTypesSupported(new LinkedHashMap<>(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA")))));

        CredentialConfigurationDTO mapped = ldpVcConfig();
        mapped.setCryptographicBindingMethodsSupported(stored.getCryptographicBindingMethodsSupported());
        mapped.setCredentialSigningAlgValuesSupported(stored.getCredentialSigningAlgValuesSupported());
        mapped.setProofTypesSupported(stored.getProofTypesSupported());

        when(credentialConfigRepository.findByCredentialConfigKeyId("test-credential")).thenReturn(Optional.of(stored));
        when(credentialConfigMapper.toDto(stored)).thenReturn(mapped);

        CredentialConfigurationDTO result = credentialConfigurationService.getCredentialConfigurationById("test-credential");

        Assert.assertEquals(List.of("did:web"), result.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(List.of("EdDSA"), result.getCredentialSigningAlgValuesSupported());
        Assert.assertEquals(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA"))), result.getProofTypesSupported());
    }

    /**
     * A configuration created before these attributes were stored keeps returning what it always has:
     * its signing algorithms resolved from the crypto suite name it stored, and the declared defaults for
     * the other two.
     */
    @Test
    public void should_returnResolvedDefaults_when_legacyConfigurationIsFetched() {
        CredentialConfig legacy = ldpVcEntity();
        legacy.setCredentialSigningAlgValuesSupported(List.of("Ed25519Signature2020"));

        when(credentialConfigRepository.findByCredentialConfigKeyId("test-credential")).thenReturn(Optional.of(legacy));
        when(credentialConfigMapper.toDto(legacy)).thenReturn(ldpVcConfig());

        CredentialConfigurationDTO result = credentialConfigurationService.getCredentialConfigurationById("test-credential");

        Assert.assertEquals(List.of("EdDSA"), result.getCredentialSigningAlgValuesSupported());
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
        Assert.assertEquals(List.of("EdDSA"), supported.getCredentialSigningAlgValuesSupported());
        Assert.assertEquals(List.of("did:web"), supported.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA"))), supported.getProofTypesSupported());
    }

    /**
     * A configuration created before this change stored the crypto suite name; it must keep advertising
     * exactly what it advertised before, with no data migration.
     */
    @Test
    public void should_advertiseUnchangedValues_when_configurationIsLegacy() {
        CredentialConfig legacy = ldpVcEntity();
        legacy.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        legacy.setCredentialSigningAlgValuesSupported(List.of("Ed25519Signature2020"));

        when(credentialConfigRepository.findAll()).thenReturn(List.of(legacy));
        when(credentialConfigMapper.toDto(legacy)).thenReturn(ldpVcConfig());

        CredentialIssuerMetadataDTO metadata = credentialConfigurationService.fetchCredentialIssuerMetadata();

        CredentialConfigurationSupportedDTO supported =
                metadata.getCredentialConfigurationSupportedDTO().get("test-credential");
        Assert.assertEquals(List.of("EdDSA"), supported.getCredentialSigningAlgValuesSupported());
        Assert.assertEquals(List.of("did:jwk"), supported.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(Set.of("jwt"), supported.getProofTypesSupported().keySet());
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
     * A legacy mso_mdoc row stores the crypto suite name, which still expands to whatever the deployment
     * declares for it. Writes reject an algorithm with no COSE equivalent, so a row that still resolves to
     * one is a stored value that has to be corrected. It is left out of the metadata rather than
     * advertised with something the format cannot carry, and every other configuration is still served.
     */
    @Test
    public void should_omitOnlyInvalidConfiguration_when_legacyMsoMdocAlgorithmIsUnmappable() {
        LinkedHashMap<String, List<String>> signingAlgs = new LinkedHashMap<>();
        signingAlgs.put("EcdsaSecp256r1Signature2019", List.of("ES256", "PS256"));
        ReflectionTestUtils.setField(credentialConfigurationService, "credentialSigningAlgValuesSupportedMap", signingAlgs);
        CredentialConfig legacy = msoMdocEntity();
        legacy.setCredentialSigningAlgValuesSupported(List.of("EcdsaSecp256r1Signature2019"));
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
        LinkedHashMap<String, List<String>> signingAlgs = new LinkedHashMap<>();
        signingAlgs.put("EcdsaSecp256r1Signature2019", List.of("ES256", "PS256"));
        ReflectionTestUtils.setField(credentialConfigurationService, "credentialSigningAlgValuesSupportedMap", signingAlgs);
        CredentialConfig legacy = msoMdocEntity();
        legacy.setCredentialSigningAlgValuesSupported(List.of("EcdsaSecp256r1Signature2019"));

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
