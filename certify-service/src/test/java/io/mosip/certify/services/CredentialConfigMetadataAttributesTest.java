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

import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Covers the per-credential-configuration selection of cryptographic_binding_methods_supported,
 * credential_signing_alg_values_supported and proof_types_supported: what is accepted, what is
 * rejected, what the defaults resolve to when an attribute is omitted, and what reaches the
 * credential issuer metadata.
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

    private CredentialConfigurationDTO ldpVcRequest() {
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

    private CredentialConfig ldpVcEntity() {
        CredentialConfig entity = new CredentialConfig();
        entity.setCredentialConfigKeyId("test-credential");
        entity.setStatus("active");
        entity.setCredentialFormat("ldp_vc");
        entity.setSignatureCryptoSuite("Ed25519Signature2020");
        entity.setSignatureAlgo("EdDSA");
        return entity;
    }

    private CredentialConfigurationDTO sdJwtRequest() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId("test-sd-jwt");
        dto.setMetaDataDisplay(List.of(new MetaDataDisplayDTO()));
        dto.setVcTemplate("test_template");
        dto.setCredentialFormat("dc+sd-jwt");
        dto.setSdJwtVct("test-vct");
        dto.setSignatureAlgo("ES256");
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

    private CredentialConfigurationDTO msoMdocRequest() {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId("test-mso-mdoc");
        dto.setMetaDataDisplay(List.of(new MetaDataDisplayDTO()));
        dto.setVcTemplate("test_template");
        dto.setCredentialFormat("mso_mdoc");
        dto.setDocType("org.iso.18013.5.1.mDL");
        dto.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
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

    // ---------- AC-1, BR-BM-3, BR-ALG-3, BR-PT-5: omitted attributes fall back to the derived defaults ----------

    @Test
    public void addWithAllThreeOmitted_StoresDerivedDefaults() {
        CredentialConfig entity = ldpVcEntity();
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);

        credentialConfigurationService.addCredentialConfiguration(ldpVcRequest());

        Assert.assertEquals(List.of("did:jwk", "did:web"), entity.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(List.of("EdDSA"), entity.getCredentialSigningAlgValuesSupported());
        Assert.assertEquals(Set.of("jwt"), entity.getProofTypesSupported().keySet());
    }

    /**
     * BR-ALG-3: the algorithms declared for the crypto suite are stored, not the crypto suite name.
     */
    @Test
    public void addWithSigningAlgsOmitted_StoresAlgorithmsRatherThanCryptoSuiteName() {
        CredentialConfig entity = ldpVcEntity();
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);

        credentialConfigurationService.addCredentialConfiguration(ldpVcRequest());

        Assert.assertEquals(List.of("EdDSA"), entity.getCredentialSigningAlgValuesSupported());
        Assert.assertFalse(entity.getCredentialSigningAlgValuesSupported().contains("Ed25519Signature2020"));
    }

    /**
     * BR-ALG-4: with no crypto suite the configuration's own signature algorithm is stored.
     */
    @Test
    public void addWithoutCryptoSuite_StoresConfigurationSignatureAlgo() {
        CredentialConfig entity = sdJwtEntity();
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);

        credentialConfigurationService.addCredentialConfiguration(sdJwtRequest());

        Assert.assertEquals(List.of("ES256"), entity.getCredentialSigningAlgValuesSupported());
    }

    // ---------- AC-2: explicitly selected values are stored as requested ----------

    @Test
    public void addWithAllThreeDeclared_StoresExactlyWhatWasRequested() {
        CredentialConfig entity = ldpVcEntity();
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        request.setCredentialSigningAlgValuesSupported(List.of("EdDSA"));
        request.setProofTypesSupported(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA"))));
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);

        credentialConfigurationService.addCredentialConfiguration(request);

        Assert.assertEquals(List.of("did:jwk"), entity.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(List.of("EdDSA"), entity.getCredentialSigningAlgValuesSupported());
        Assert.assertEquals(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA"))), entity.getProofTypesSupported());
    }

    /**
     * BR-PT-3: naming a proof type without narrowing it leaves every declared algorithm applying.
     */
    @Test
    public void addWithProofTypeAndNoAlgorithmList_StoresTheFullDeclaredSet() {
        CredentialConfig entity = ldpVcEntity();
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setProofTypesSupported(new LinkedHashMap<>(Map.of("jwt", Map.of())));
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);

        credentialConfigurationService.addCredentialConfiguration(request);

        // Storing the bare proof type would advertise no algorithms at all, and JwtProofValidator reads a
        // missing proof_signing_alg_values_supported as an empty list and rejects every proof.
        Assert.assertEquals(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("RS256", "PS256", "ES256", "EdDSA"))),
                entity.getProofTypesSupported());
    }

    /**
     * BR-PT-3: the same applies when the proof type carries no object at all.
     */
    @Test
    public void addWithProofTypeAndNullDetail_StoresTheFullDeclaredSet() {
        CredentialConfig entity = ldpVcEntity();
        CredentialConfigurationDTO request = ldpVcRequest();
        LinkedHashMap<String, Object> proofTypes = new LinkedHashMap<>();
        proofTypes.put("jwt", null);
        request.setProofTypesSupported(proofTypes);
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);

        credentialConfigurationService.addCredentialConfiguration(request);

        Assert.assertEquals(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("RS256", "PS256", "ES256", "EdDSA"))),
                entity.getProofTypesSupported());
    }

    /**
     * BR-PT-3 reaching the credential issuer metadata: what a wallet sees carries the algorithms, so the
     * published metadata stays valid under OpenID4VCI.
     */
    @Test
    public void metadata_ForProofTypeWithNoAlgorithmList_AdvertisesTheFullDeclaredSet() {
        CredentialConfig stored = ldpVcEntity();
        stored.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        stored.setCredentialSigningAlgValuesSupported(List.of("EdDSA"));
        LinkedHashMap<String, Object> bare = new LinkedHashMap<>();
        bare.put("jwt", Map.of());
        stored.setProofTypesSupported(bare);

        CredentialConfigurationDTO mapped = ldpVcRequest();
        mapped.setProofTypesSupported(bare);
        when(credentialConfigRepository.findByCredentialConfigKeyId("test-credential")).thenReturn(Optional.of(stored));
        when(credentialConfigMapper.toDto(stored)).thenReturn(mapped);

        CredentialConfigurationDTO result = credentialConfigurationService.getCredentialConfigurationById("test-credential");

        Assert.assertEquals(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("RS256", "PS256", "ES256", "EdDSA"))),
                result.getProofTypesSupported());
    }

    /**
     * BR-ALG-2: with no crypto suite the allow-list is the key selection configuration.
     */
    @Test
    public void addSdJwtWithAlgorithmHoldingASigningKey_IsAccepted() {
        CredentialConfig entity = sdJwtEntity();
        CredentialConfigurationDTO request = sdJwtRequest();
        request.setCredentialSigningAlgValuesSupported(List.of("ES256"));
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);

        credentialConfigurationService.addCredentialConfiguration(request);

        Assert.assertEquals(List.of("ES256"), entity.getCredentialSigningAlgValuesSupported());
    }

    // ---------- AC-3, BR-CM-3: undeclared values are rejected and nothing is saved ----------

    @Test
    public void addWithUndeclaredBindingMethod_IsRejected() {
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
     * BR-BM-2: a format the deployment declares no binding methods for.
     */
    @Test
    public void addWithBindingMethodsForUndeclaredFormat_IsRejected() {
        ReflectionTestUtils.setField(credentialConfigurationService, "cryptographicBindingMethodsSupportedMap",
                new LinkedHashMap<String, List<String>>());
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setCryptographicBindingMethodsSupported(List.of("did:jwk"));

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(ErrorConstants.CRYPTOGRAPHIC_BINDING_CONFIG_NOT_FOUND,
                exception.getErrors().getFirst().getErrorCode());
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    @Test
    public void addWithAlgorithmNotDeclaredForCryptoSuite_IsRejected() {
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
     * BR-ALG-2: an algorithm the deployment holds no signing key for.
     */
    @Test
    public void addSdJwtWithAlgorithmHoldingNoSigningKey_IsRejected() {
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
    public void addMsoMdocWithAlgorithmHavingNoCoseEquivalent_IsRejected() {
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
     * Omitting the attribute must not be a way round the COSE check: the algorithms derived from the
     * deployment's own declaration are what gets stored, and for mso_mdoc they have to convert too.
     */
    @Test
    public void addMsoMdocWithSigningAlgsOmittedAndSuiteDeclaringNoCoseEquivalent_IsRejected() {
        LinkedHashMap<String, List<String>> signingAlgs = new LinkedHashMap<>();
        signingAlgs.put("EcdsaSecp256r1Signature2019", List.of("ES256", "PS256"));
        ReflectionTestUtils.setField(credentialConfigurationService, "credentialSigningAlgValuesSupportedMap", signingAlgs);
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(msoMdocEntity());

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(msoMdocRequest()));

        Assert.assertEquals(ErrorConstants.UNSUPPORTED_CREDENTIAL_SIGNING_ALG,
                exception.getErrors().getFirst().getErrorCode());
        Assert.assertTrue(exception.getErrors().getFirst().getErrorMessage().contains("PS256"));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * The COSE restriction applies to mso_mdoc alone; every other format keeps the crypto suite's own
     * declared algorithms.
     */
    @Test
    public void addWithAlgorithmHavingNoCoseEquivalent_IsAcceptedForOtherFormats() {
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

    /**
     * A proof type the deployment declares with no signing algorithms would be stored, and advertised,
     * carrying none - which OpenID4VCI does not allow and which makes JwtProofValidator reject every
     * proof. The misconfiguration is reported instead of being persisted.
     */
    @Test
    public void addWithProofTypeDeclaringNoSigningAlgs_IsRejected() {
        LinkedHashMap<String, Object> proofTypes = new LinkedHashMap<>();
        proofTypes.put("jwt", Map.of(PROOF_SIGNING_ALGS, List.of()));
        ReflectionTestUtils.setField(credentialConfigurationService, "proofTypesSupported", proofTypes);
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setProofTypesSupported(Map.of("jwt", Map.of()));

        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertTrue(exception.getMessage().contains(PROOF_SIGNING_ALGS));
        Assert.assertTrue(exception.getMessage().contains("jwt"));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * Omitting the attribute must not be a way round that check: the derived default is resolved the
     * same way a requested value is.
     */
    @Test
    public void addWithProofTypesOmittedAndDeclaredWithoutSigningAlgs_IsRejected() {
        LinkedHashMap<String, Object> proofTypes = new LinkedHashMap<>();
        proofTypes.put("jwt", Map.of(PROOF_SIGNING_ALGS, List.of()));
        ReflectionTestUtils.setField(credentialConfigurationService, "proofTypesSupported", proofTypes);
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());

        assertThrows(IllegalStateException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(ldpVcRequest()));

        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * BR-PT-1: an undeclared proof type.
     */
    @Test
    public void addWithUndeclaredProofType_IsRejected() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setProofTypesSupported(Map.of("ldp_vp", Map.of()));

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(ErrorConstants.UNSUPPORTED_PROOF_TYPE, exception.getErrors().getFirst().getErrorCode());
        Assert.assertTrue(exception.getErrors().getFirst().getErrorMessage().contains("jwt"));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * BR-PT-2: a proof signing algorithm outside the set declared for that proof type.
     */
    @Test
    public void addWithUndeclaredProofSigningAlgorithm_IsRejected() {
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
     * BR-PT-4: an attribute the deployment does not recognise inside a proof type entry.
     */
    @Test
    public void addWithUnrecognisedProofTypeAttribute_IsRejected() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setProofTypesSupported(Map.of("jwt", Map.of("unknown_attribute", List.of("EdDSA"))));

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(ErrorConstants.INVALID_REQUEST, exception.getErrors().getFirst().getErrorCode());
        Assert.assertTrue(exception.getErrors().getFirst().getErrorMessage().contains("unknown_attribute"));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    // ---------- BR-CM-1: present but empty ----------

    /**
     * Binding methods and proof types empty together configure the credential without holder binding
     * (covered below), so each is rejected here when it is empty on its own.
     */
    @Test
    public void addWithEmptyAttributes_IsRejected() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setCryptographicBindingMethodsSupported(List.of());
        request.setCredentialSigningAlgValuesSupported(List.of());

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(2, exception.getErrors().size());
        exception.getErrors().forEach(error ->
                Assert.assertEquals(ErrorConstants.INVALID_REQUEST, error.getErrorCode()));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    // ---------- Every failure is reported in one pass ----------

    @Test
    public void addWithSeveralInvalidValues_ReportsThemTogether() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setCryptographicBindingMethodsSupported(List.of("cose_key"));
        request.setCredentialSigningAlgValuesSupported(List.of("RS256"));
        request.setProofTypesSupported(Map.of("ldp_vp", Map.of()));

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        List<String> errorCodes = exception.getErrors().stream().map(io.mosip.certify.core.dto.Error::getErrorCode).toList();
        Assert.assertEquals(3, errorCodes.size());
        Assert.assertTrue(errorCodes.contains(ErrorConstants.UNSUPPORTED_CRYPTOGRAPHIC_BINDING_METHOD));
        Assert.assertTrue(errorCodes.contains(ErrorConstants.UNSUPPORTED_CREDENTIAL_SIGNING_ALG));
        Assert.assertTrue(errorCodes.contains(ErrorConstants.UNSUPPORTED_PROOF_TYPE));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    // ---------- AC-4, AC-5, BR-CM-2: update replaces what is present and retains what is omitted ----------

    @Test
    public void updateWithAttributesPresent_ReplacesStoredValues() {
        CredentialConfig stored = ldpVcEntity();
        stored.setCryptographicBindingMethodsSupported(List.of("did:jwk", "did:web"));
        stored.setCredentialSigningAlgValuesSupported(List.of("EdDSA"));
        stored.setProofTypesSupported(new LinkedHashMap<>(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("RS256", "EdDSA")))));

        CredentialConfigurationDTO request = new CredentialConfigurationDTO();
        request.setCryptographicBindingMethodsSupported(List.of("did:web"));
        request.setCredentialSigningAlgValuesSupported(List.of("EdDSA"));
        request.setProofTypesSupported(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA"))));

        when(credentialConfigRepository.findByCredentialConfigKeyId("test-credential")).thenReturn(Optional.of(stored));
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(ldpVcRequest());
        doNothing().when(credentialConfigMapper).updateEntityFromDto(any(CredentialConfigurationDTO.class), any(CredentialConfig.class));
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(stored);

        credentialConfigurationService.updateCredentialConfiguration("test-credential", request);

        Assert.assertEquals(List.of("did:web"), stored.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA"))), stored.getProofTypesSupported());
    }

    /**
     * AC-5 and BR-CM-2: an omitted attribute keeps its stored value and is never re-derived from the
     * current deployment configuration.
     */
    @Test
    public void updateWithAttributesOmitted_RetainsStoredValues() {
        CredentialConfig stored = ldpVcEntity();
        stored.setCryptographicBindingMethodsSupported(List.of("did:web"));
        stored.setCredentialSigningAlgValuesSupported(List.of("EdDSA"));
        stored.setProofTypesSupported(new LinkedHashMap<>(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA")))));

        when(credentialConfigRepository.findByCredentialConfigKeyId("test-credential")).thenReturn(Optional.of(stored));
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(ldpVcRequest());
        doNothing().when(credentialConfigMapper).updateEntityFromDto(any(CredentialConfigurationDTO.class), any(CredentialConfig.class));
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(stored);

        credentialConfigurationService.updateCredentialConfiguration("test-credential", new CredentialConfigurationDTO());

        Assert.assertEquals(List.of("did:web"), stored.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(List.of("EdDSA"), stored.getCredentialSigningAlgValuesSupported());
        Assert.assertEquals(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA"))), stored.getProofTypesSupported());
    }

    @Test
    public void updateWithUndeclaredValue_IsRejectedAndNothingIsSaved() {
        CredentialConfig stored = ldpVcEntity();
        CredentialConfigurationDTO request = new CredentialConfigurationDTO();
        request.setCryptographicBindingMethodsSupported(List.of("cose_key"));

        when(credentialConfigRepository.findByCredentialConfigKeyId("test-credential")).thenReturn(Optional.of(stored));
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(ldpVcRequest());
        doNothing().when(credentialConfigMapper).updateEntityFromDto(any(CredentialConfigurationDTO.class), any(CredentialConfig.class));

        assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.updateCredentialConfiguration("test-credential", request));

        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * BR-CM-4: a stored value the deployment has stopped declaring surfaces on the next update rather
     * than drifting silently, even though the attribute is omitted from the request.
     */
    @Test
    public void updateRetainingAValueTheDeploymentNoLongerDeclares_IsRejected() {
        LinkedHashMap<String, List<String>> narrowedBindingMethods = new LinkedHashMap<>();
        narrowedBindingMethods.put("ldp_vc", List.of("did:jwk"));
        ReflectionTestUtils.setField(credentialConfigurationService, "cryptographicBindingMethodsSupportedMap",
                narrowedBindingMethods);

        CredentialConfig stored = ldpVcEntity();
        stored.setCryptographicBindingMethodsSupported(List.of("did:web"));

        when(credentialConfigRepository.findByCredentialConfigKeyId("test-credential")).thenReturn(Optional.of(stored));
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(ldpVcRequest());
        doNothing().when(credentialConfigMapper).updateEntityFromDto(any(CredentialConfigurationDTO.class), any(CredentialConfig.class));

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.updateCredentialConfiguration("test-credential", new CredentialConfigurationDTO()));

        Assert.assertEquals(ErrorConstants.UNSUPPORTED_CRYPTOGRAPHIC_BINDING_METHOD,
                exception.getErrors().getFirst().getErrorCode());
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * A configuration created before this change is updated for an unrelated field: the three attributes
     * are retained and the update succeeds, with the stored crypto suite name corrected to the algorithms
     * it stands for.
     */
    @Test
    public void updateLegacyConfiguration_SucceedsAndCorrectsTheStoredSigningAlgorithms() {
        CredentialConfig legacy = ldpVcEntity();
        legacy.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        legacy.setCredentialSigningAlgValuesSupported(List.of("Ed25519Signature2020"));
        legacy.setProofTypesSupported(new LinkedHashMap<>(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("RS256", "PS256", "ES256", "EdDSA")))));

        when(credentialConfigRepository.findByCredentialConfigKeyId("test-credential")).thenReturn(Optional.of(legacy));
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(ldpVcRequest());
        doNothing().when(credentialConfigMapper).updateEntityFromDto(any(CredentialConfigurationDTO.class), any(CredentialConfig.class));
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(legacy);

        credentialConfigurationService.updateCredentialConfiguration("test-credential", new CredentialConfigurationDTO());

        Assert.assertEquals(List.of("EdDSA"), legacy.getCredentialSigningAlgValuesSupported());
        Assert.assertEquals(List.of("did:jwk"), legacy.getCryptographicBindingMethodsSupported());
    }

    // ---------- AC-6, AC-7: the Get response always carries all three ----------

    @Test
    public void getConfiguration_ReturnsStoredValues() {
        CredentialConfig stored = ldpVcEntity();
        stored.setCryptographicBindingMethodsSupported(List.of("did:web"));
        stored.setCredentialSigningAlgValuesSupported(List.of("EdDSA"));
        stored.setProofTypesSupported(new LinkedHashMap<>(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA")))));

        CredentialConfigurationDTO mapped = ldpVcRequest();
        mapped.setCryptographicBindingMethodsSupported(stored.getCryptographicBindingMethodsSupported());
        mapped.setCredentialSigningAlgValuesSupported(stored.getCredentialSigningAlgValuesSupported());
        mapped.setProofTypesSupported(stored.getProofTypesSupported());

        when(credentialConfigRepository.findByCredentialConfigKeyId("test-credential")).thenReturn(Optional.of(stored));
        when(credentialConfigMapper.toDto(stored)).thenReturn(mapped);

        CredentialConfigurationDTO result = credentialConfigurationService.getCredentialConfigurationById("test-credential");

        Assert.assertEquals(List.of("did:web"), result.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(List.of("EdDSA"), result.getCredentialSigningAlgValuesSupported());
        Assert.assertEquals(Set.of("jwt"), result.getProofTypesSupported().keySet());
    }

    /**
     * AC-7: a configuration created before this change resolves its signing algorithms from the crypto
     * suite name it stored, rather than returning that suite name.
     */
    @Test
    public void getLegacyConfiguration_ReturnsResolvedDefaults() {
        CredentialConfig legacy = ldpVcEntity();
        // Legacy rows always store binding methods; 0.14.0 stored empty proof types to mean the defaults.
        legacy.setCryptographicBindingMethodsSupported(List.of("did:jwk", "did:web"));
        legacy.setCredentialSigningAlgValuesSupported(List.of("Ed25519Signature2020"));
        legacy.setProofTypesSupported(new LinkedHashMap<>());

        when(credentialConfigRepository.findByCredentialConfigKeyId("test-credential")).thenReturn(Optional.of(legacy));
        when(credentialConfigMapper.toDto(legacy)).thenReturn(ldpVcRequest());

        CredentialConfigurationDTO result = credentialConfigurationService.getCredentialConfigurationById("test-credential");

        Assert.assertEquals(List.of("EdDSA"), result.getCredentialSigningAlgValuesSupported());
        Assert.assertEquals(List.of("did:jwk", "did:web"), result.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(Set.of("jwt"), result.getProofTypesSupported().keySet());
    }

    // ---------- AC-8 and the metadata stability requirement ----------

    @Test
    public void metadata_AdvertisesTheValuesStoredAgainstTheConfiguration() {
        CredentialConfig stored = ldpVcEntity();
        stored.setCryptographicBindingMethodsSupported(List.of("did:web"));
        stored.setCredentialSigningAlgValuesSupported(List.of("EdDSA"));
        stored.setProofTypesSupported(new LinkedHashMap<>(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA")))));

        when(credentialConfigRepository.findAll()).thenReturn(List.of(stored));
        when(credentialConfigMapper.toDto(stored)).thenReturn(ldpVcRequest());

        CredentialIssuerMetadataDTO metadata = credentialConfigurationService.fetchCredentialIssuerMetadata();

        CredentialConfigurationSupportedDTO supported =
                metadata.getCredentialConfigurationSupportedDTO().get("test-credential");
        Assert.assertEquals(List.of("EdDSA"), supported.getCredentialSigningAlgValuesSupported());
        Assert.assertEquals(List.of("did:web"), supported.getCryptographicBindingMethodsSupported());
        Assert.assertEquals(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA"))), supported.getProofTypesSupported());
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
        when(credentialConfigMapper.toDto(legacy)).thenReturn(msoMdocRequest());
        when(credentialConfigMapper.toDto(healthy)).thenReturn(ldpVcRequest());

        CredentialIssuerMetadataDTO metadata = credentialConfigurationService.fetchCredentialIssuerMetadata();

        Assert.assertEquals(Set.of("test-credential"), metadata.getCredentialConfigurationSupportedDTO().keySet());
    }

    /**
     * A stored proof type the deployment no longer declares any signing algorithm for cannot be advertised
     * either. Before, the exception escaped and the endpoint failed for every credential type.
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
        when(credentialConfigMapper.toDto(broken)).thenReturn(sdJwtRequest());
        when(credentialConfigMapper.toDto(healthy)).thenReturn(ldpVcRequest());

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
        when(credentialConfigMapper.toDto(legacy)).thenReturn(msoMdocRequest());

        credentialConfigurationService.validateStoredConfigurations();

        verify(credentialConfigMapper).toDto(legacy);
    }

    /**
     * A configuration created before this change stored the crypto suite name; it must keep advertising
     * exactly what it advertised before, with no data migration.
     */
    @Test
    public void metadata_ForLegacyConfiguration_IsUnchanged() {
        CredentialConfig legacy = ldpVcEntity();
        legacy.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        legacy.setCredentialSigningAlgValuesSupported(List.of("Ed25519Signature2020"));

        when(credentialConfigRepository.findAll()).thenReturn(List.of(legacy));
        when(credentialConfigMapper.toDto(legacy)).thenReturn(ldpVcRequest());

        CredentialIssuerMetadataDTO metadata = credentialConfigurationService.fetchCredentialIssuerMetadata();

        Assert.assertEquals(List.of("EdDSA"), metadata.getCredentialConfigurationSupportedDTO()
                .get("test-credential").getCredentialSigningAlgValuesSupported());
    }

    // ---------- Optional holder binding: binding methods and proof types both empty ----------

    @Test
    public void addWithBindingMethodsAndProofTypesEmpty_StoresConfigurationWithoutHolderBinding() {
        CredentialConfig entity = ldpVcEntity();
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setCryptographicBindingMethodsSupported(List.of());
        request.setProofTypesSupported(Map.of());
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);

        credentialConfigurationService.addCredentialConfiguration(request);

        Assert.assertNull(entity.getCryptographicBindingMethodsSupported());
        Assert.assertNull(entity.getProofTypesSupported());
        Assert.assertEquals(List.of("EdDSA"), entity.getCredentialSigningAlgValuesSupported());
    }

    /**
     * The VC issuance plugin always issues holder-bound credentials, so a configuration it could never
     * issue is rejected instead of being advertised as needing no proof.
     */
    @Test
    public void addWithoutHolderBinding_InVCIssuanceMode_IsRejected() {
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "VCIssuance");
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setCryptographicBindingMethodsSupported(List.of());
        request.setProofTypesSupported(Map.of());

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(ErrorConstants.UNSUPPORTED_IN_CURRENT_PLUGIN_MODE, exception.getErrors().getFirst().getErrorCode());
        Assert.assertEquals("Credentials without holder binding are not supported in the VCIssuance plugin mode.",
                exception.getErrors().getFirst().getErrorMessage());
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    @Test
    public void updateWithBindingMethodsAndProofTypesEmpty_InVCIssuanceMode_IsRejected() {
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "VCIssuance");
        CredentialConfig stored = ldpVcEntity();
        stored.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        stored.setProofTypesSupported(new LinkedHashMap<>(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA")))));
        CredentialConfigurationDTO request = new CredentialConfigurationDTO();
        request.setCryptographicBindingMethodsSupported(List.of());
        request.setProofTypesSupported(Map.of());

        when(credentialConfigRepository.findByCredentialConfigKeyId("test-credential")).thenReturn(Optional.of(stored));
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(ldpVcRequest());
        doNothing().when(credentialConfigMapper).updateEntityFromDto(any(CredentialConfigurationDTO.class), any(CredentialConfig.class));

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.updateCredentialConfiguration("test-credential", request));

        Assert.assertEquals(ErrorConstants.UNSUPPORTED_IN_CURRENT_PLUGIN_MODE, exception.getErrors().getFirst().getErrorCode());
        Assert.assertEquals(List.of("did:jwk"), stored.getCryptographicBindingMethodsSupported());
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * A configuration stored without holder binding, for example before the deployment switched plugin
     * mode, is not kept unbound by an update that omits both attributes.
     */
    @Test
    public void updateConfigurationWithoutHolderBinding_InVCIssuanceMode_IsRejected() {
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "VCIssuance");
        CredentialConfig stored = ldpVcEntity();
        stored.setCredentialSigningAlgValuesSupported(List.of("EdDSA"));

        when(credentialConfigRepository.findByCredentialConfigKeyId("test-credential")).thenReturn(Optional.of(stored));
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(ldpVcRequest());
        doNothing().when(credentialConfigMapper).updateEntityFromDto(any(CredentialConfigurationDTO.class), any(CredentialConfig.class));

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.updateCredentialConfiguration("test-credential", new CredentialConfigurationDTO()));

        Assert.assertEquals(ErrorConstants.UNSUPPORTED_IN_CURRENT_PLUGIN_MODE, exception.getErrors().getFirst().getErrorCode());
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    @Test
    public void addWithHolderBinding_InVCIssuanceMode_IsStored() {
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "VCIssuance");
        CredentialConfig entity = ldpVcEntity();
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);

        credentialConfigurationService.addCredentialConfiguration(ldpVcRequest());

        Assert.assertNotNull(entity.getCryptographicBindingMethodsSupported());
        Assert.assertNotNull(entity.getProofTypesSupported());
    }

    /**
     * Configurations without holder binding are rejected in VCIssuance mode, so the message for an empty
     * attribute does not suggest configuring one.
     */
    @Test
    public void addWithOnlyBindingMethodsEmpty_InVCIssuanceMode_IsRejectedWithoutWithoutHolderBindingHint() {
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "VCIssuance");
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setCryptographicBindingMethodsSupported(List.of());

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals("cryptographicBindingMethodsSupported was provided but is empty.",
                exception.getErrors().getFirst().getErrorMessage());
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    @Test
    public void addWithAttributesOmitted_InVCIssuanceMode_ForFormatWithoutDeclaredBindingMethods_HasNoWithoutHolderBindingHint() {
        ReflectionTestUtils.setField(credentialConfigurationService, "pluginMode", "VCIssuance");
        ReflectionTestUtils.setField(credentialConfigurationService, "cryptographicBindingMethodsSupportedMap",
                new LinkedHashMap<>(Map.of("mso_mdoc", List.of("cose_key"))));
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(ldpVcRequest()));

        Assert.assertEquals(ErrorConstants.CRYPTOGRAPHIC_BINDING_CONFIG_NOT_FOUND, exception.getErrors().getFirst().getErrorCode());
        Assert.assertFalse(exception.getErrors().getFirst().getErrorMessage().contains("without holder binding"));
    }

    @Test
    public void addWithOnlyProofTypesEmpty_IsRejected() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        request.setProofTypesSupported(Map.of());

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(ErrorConstants.INVALID_REQUEST, exception.getErrors().getFirst().getErrorCode());
        Assert.assertEquals("proofTypesSupported was provided but is empty. To configure a credential without holder "
                        + "binding, send both cryptographicBindingMethodsSupported and proofTypesSupported empty.",
                exception.getErrors().getFirst().getErrorMessage());
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    @Test
    public void addWithOnlyBindingMethodsEmpty_IsRejectedWithWithoutHolderBindingHint() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setCryptographicBindingMethodsSupported(List.of());

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(ErrorConstants.INVALID_REQUEST, exception.getErrors().getFirst().getErrorCode());
        Assert.assertEquals("cryptographicBindingMethodsSupported was provided but is empty. To configure a credential "
                        + "without holder binding, send both cryptographicBindingMethodsSupported and proofTypesSupported empty.",
                exception.getErrors().getFirst().getErrorMessage());
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * mso_mdoc cannot be configured without holder binding, so its message does not suggest it.
     */
    @Test
    public void addMsoMdocWithOnlyBindingMethodsEmpty_IsRejectedWithoutWithoutHolderBindingHint() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(msoMdocEntity());
        CredentialConfigurationDTO request = msoMdocRequest();
        request.setCryptographicBindingMethodsSupported(List.of());

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertTrue(exception.getErrors().stream().anyMatch(error ->
                error.getErrorMessage().equals("cryptographicBindingMethodsSupported was provided but is empty.")));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * ISO/IEC 18013-5 requires deviceKeyInfo in the mobile security object, so mso_mdoc is always bound.
     */
    @Test
    public void addMsoMdocWithBindingMethodsAndProofTypesEmpty_IsRejected() {
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(msoMdocEntity());
        CredentialConfigurationDTO request = msoMdocRequest();
        request.setCryptographicBindingMethodsSupported(List.of());
        request.setProofTypesSupported(Map.of());

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(ErrorConstants.INVALID_REQUEST, exception.getErrors().getFirst().getErrorCode());
        Assert.assertTrue(exception.getErrors().getFirst().getErrorMessage().contains("mso_mdoc"));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    /**
     * Omitting both attributes derives the binding methods declared for the format. With none declared the
     * configuration would advertise an empty list next to proof types, so it is rejected.
     */
    @Test
    public void addWithAttributesOmitted_ForFormatWithoutDeclaredBindingMethods_IsRejected() {
        ReflectionTestUtils.setField(credentialConfigurationService, "cryptographicBindingMethodsSupportedMap",
                new LinkedHashMap<>(Map.of("mso_mdoc", List.of("cose_key"))));
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(ldpVcEntity());
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setCryptographicBindingMethodsSupported(null);
        request.setProofTypesSupported(null);

        CredentialConfigValidationException exception = assertThrows(CredentialConfigValidationException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));

        Assert.assertEquals(ErrorConstants.CRYPTOGRAPHIC_BINDING_CONFIG_NOT_FOUND, exception.getErrors().getFirst().getErrorCode());
        Assert.assertTrue(exception.getErrors().getFirst().getErrorMessage().contains("without holder binding"));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    @Test
    public void addWithoutHolderBinding_ForFormatWithoutDeclaredBindingMethods_IsStored() {
        ReflectionTestUtils.setField(credentialConfigurationService, "cryptographicBindingMethodsSupportedMap",
                new LinkedHashMap<>(Map.of("mso_mdoc", List.of("cose_key"))));
        CredentialConfig entity = ldpVcEntity();
        CredentialConfigurationDTO request = ldpVcRequest();
        request.setCryptographicBindingMethodsSupported(List.of());
        request.setProofTypesSupported(Map.of());
        when(credentialConfigMapper.toEntity(any(CredentialConfigurationDTO.class))).thenReturn(entity);
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(entity);

        credentialConfigurationService.addCredentialConfiguration(request);

        Assert.assertNull(entity.getCryptographicBindingMethodsSupported());
        Assert.assertNull(entity.getProofTypesSupported());
    }

    @Test
    public void updateConfigurationWithoutHolderBinding_WithAttributesOmitted_StaysWithoutHolderBinding() {
        CredentialConfig stored = ldpVcEntity();
        stored.setCredentialSigningAlgValuesSupported(List.of("EdDSA"));

        when(credentialConfigRepository.findByCredentialConfigKeyId("test-credential")).thenReturn(Optional.of(stored));
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(ldpVcRequest());
        doNothing().when(credentialConfigMapper).updateEntityFromDto(any(CredentialConfigurationDTO.class), any(CredentialConfig.class));
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(stored);

        credentialConfigurationService.updateCredentialConfiguration("test-credential", new CredentialConfigurationDTO());

        Assert.assertNull(stored.getCryptographicBindingMethodsSupported());
        Assert.assertNull(stored.getProofTypesSupported());
    }

    @Test
    public void updateWithBindingMethodsAndProofTypesEmpty_RemovesHolderBinding() {
        CredentialConfig stored = ldpVcEntity();
        stored.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        stored.setCredentialSigningAlgValuesSupported(List.of("EdDSA"));
        stored.setProofTypesSupported(new LinkedHashMap<>(Map.of("jwt", Map.of(PROOF_SIGNING_ALGS, List.of("EdDSA")))));
        CredentialConfigurationDTO request = new CredentialConfigurationDTO();
        request.setCryptographicBindingMethodsSupported(List.of());
        request.setProofTypesSupported(Map.of());

        when(credentialConfigRepository.findByCredentialConfigKeyId("test-credential")).thenReturn(Optional.of(stored));
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenReturn(ldpVcRequest());
        doNothing().when(credentialConfigMapper).updateEntityFromDto(any(CredentialConfigurationDTO.class), any(CredentialConfig.class));
        when(credentialConfigRepository.save(any(CredentialConfig.class))).thenReturn(stored);

        credentialConfigurationService.updateCredentialConfiguration("test-credential", request);

        Assert.assertNull(stored.getCryptographicBindingMethodsSupported());
        Assert.assertNull(stored.getProofTypesSupported());
    }

    @Test
    public void getConfigurationWithoutHolderBinding_ReturnsNeitherBindingMethodsNorProofTypes() {
        CredentialConfig stored = ldpVcEntity();
        stored.setCredentialSigningAlgValuesSupported(List.of("EdDSA"));

        when(credentialConfigRepository.findByCredentialConfigKeyId("test-credential")).thenReturn(Optional.of(stored));
        when(credentialConfigMapper.toDto(stored)).thenReturn(ldpVcRequest());

        CredentialConfigurationDTO result = credentialConfigurationService.getCredentialConfigurationById("test-credential");

        Assert.assertNull(result.getCryptographicBindingMethodsSupported());
        Assert.assertNull(result.getProofTypesSupported());
        Assert.assertEquals(List.of("EdDSA"), result.getCredentialSigningAlgValuesSupported());
    }

    @Test
    public void metadata_ForConfigurationWithoutHolderBinding_AdvertisesNeitherBindingMethodsNorProofTypes() {
        CredentialConfig stored = ldpVcEntity();
        stored.setCredentialSigningAlgValuesSupported(List.of("EdDSA"));

        when(credentialConfigRepository.findAll()).thenReturn(List.of(stored));
        when(credentialConfigMapper.toDto(stored)).thenReturn(ldpVcRequest());

        CredentialConfigurationSupportedDTO supported = credentialConfigurationService.fetchCredentialIssuerMetadata()
                .getCredentialConfigurationSupportedDTO().get("test-credential");

        Assert.assertNull(supported.getCryptographicBindingMethodsSupported());
        Assert.assertNull(supported.getProofTypesSupported());
    }
}
