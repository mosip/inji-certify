package io.mosip.certify.services;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.ClaimsDTO;
import io.mosip.certify.core.dto.ClaimsDisplayFieldsConfigDTO;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.MetaDataDisplayDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.CredentialConfigMapper;
import io.mosip.certify.utils.CredentialConfigMapperImpl;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.*;

import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * An invalid sdClaim must be rejected when a dc+sd-jwt credential configuration is added or updated.
 */
@RunWith(MockitoJUnitRunner.class)
public class CredentialConfigSdClaimValidationTest {

    /** Literal on purpose: pins the error code clients receive, not just the constant's name. */
    private static final String INVALID_SD_CLAIM = "invalid_sd_claim";

    private static final String SD_JWT_KEY_ID = "sd-jwt-config";
    private static final String STORED_SD_CLAIM = "$.fullName, $.address.region, $.phoneNumbers[0]";

    @Mock
    private CredentialConfigRepository credentialConfigRepository;

    @Spy
    private CredentialConfigMapper credentialConfigMapper = new CredentialConfigMapperImpl();

    @InjectMocks
    private CredentialConfigurationServiceImpl credentialConfigurationService;

    @Before
    public void setup() {
        // The local profile's values (application-local.properties), so the unit and HTTP runs agree.
        LinkedHashMap<String, List<String>> bindingMethods = new LinkedHashMap<>();
        bindingMethods.put("ldp_vc", List.of("did:jwk", "did:web"));
        bindingMethods.put("mso_mdoc", List.of("cose_key"));
        bindingMethods.put("dc+sd-jwt", List.of("did:jwk", "did:web"));

        LinkedHashMap<String, List<String>> signingAlgs = new LinkedHashMap<>();
        signingAlgs.put("Ed25519Signature2020", List.of("EdDSA"));
        signingAlgs.put("EcdsaSecp256r1Signature2019", List.of("ES256"));

        LinkedHashMap<String, Object> proofTypes = new LinkedHashMap<>();
        proofTypes.put("jwt", Map.of(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED,
                List.of("RS256", "PS256", "ES256", "EdDSA")));

        Map<String, List<List<String>>> keyAliasMapper = new HashMap<>();
        keyAliasMapper.put("EdDSA", List.of(List.of("CERTIFY_VC_SIGN_ED25519", "ED25519_SIGN")));
        keyAliasMapper.put("ES256", List.of(List.of("CERTIFY_VC_SIGN_EC_R1", "EC_SECP256R1_SIGN")));

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

        lenient().when(credentialConfigRepository.save(any(CredentialConfig.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }


    private static List<MetaDataDisplayDTO> display() {
        MetaDataDisplayDTO.Logo logo = new MetaDataDisplayDTO.Logo();
        logo.setUri("https://inji.github.io/inji-config/logos/mosipid-logo.png");
        logo.setAltText("a square logo of a MOSIP");
        MetaDataDisplayDTO display = new MetaDataDisplayDTO();
        display.setLogo(logo);
        display.setName("Ticket 1077");
        display.setLocale("en");
        display.setTextColor("#FFFFFF");
        display.setBackgroundColor("#12107c");
        return new ArrayList<>(List.of(display));
    }

    private static ClaimsDisplayFieldsConfigDTO claimDisplay(String name) {
        return new ClaimsDisplayFieldsConfigDTO(List.of(new ClaimsDisplayFieldsConfigDTO.Display(name, "en")));
    }

    /** The request collection 10's dc+sd-jwt bodies send, with the given sdClaim (null = omitted). */
    private static CredentialConfigurationDTO sdJwtRequest(String sdClaim) {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setVcTemplate("test_template");
        dto.setCredentialConfigKeyId(SD_JWT_KEY_ID);
        dto.setContextURLs(new ArrayList<>());
        dto.setCredentialTypes(new ArrayList<>());
        dto.setCredentialFormat("dc+sd-jwt");
        dto.setSdJwtVct("test-vct");
        dto.setSignatureAlgo("ES256");
        dto.setKeyManagerAppId("CERTIFY_VC_SIGN_EC_R1");
        dto.setKeyManagerRefId("EC_SECP256R1_SIGN");
        dto.setCryptographicBindingMethodsSupported(new ArrayList<>(List.of("did:jwk", "did:web")));
        dto.setCredentialSigningAlgValuesSupported(new ArrayList<>(List.of("ES256")));
        Map<String, Object> proofTypes = new LinkedHashMap<>();
        proofTypes.put("jwt", Map.of(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED,
                List.of("RS256", "PS256", "ES256", "EdDSA")));
        dto.setProofTypesSupported(proofTypes);
        dto.setMetaDataDisplay(display());
        dto.setDisplayOrder(new ArrayList<>(List.of("fullName", "dateOfBirth", "gender", "UIN", "email")));
        dto.setScope("t1077_sd_jwt");
        Map<String, ClaimsDisplayFieldsConfigDTO> claims = new LinkedHashMap<>();
        claims.put("fullName", claimDisplay("Full Name"));
        claims.put("gender", claimDisplay("Gender"));
        dto.setSdJwtClaims(claims);
        dto.setSdClaim(sdClaim);
        return dto;
    }

    private static CredentialConfigurationDTO ldpVcRequest(String sdClaim) {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setVcTemplate("test_template");
        dto.setCredentialConfigKeyId("ldp-vc-config");
        dto.setContextURLs(new ArrayList<>(List.of("https://www.w3.org/2018/credentials/v1")));
        dto.setCredentialTypes(new ArrayList<>(List.of("VerifiableCredential", "T1077Credential")));
        dto.setCredentialFormat("ldp_vc");
        dto.setDidUrl("did:web:inji.github.io:inji-config:dev-int-inji:farmer");
        dto.setKeyManagerAppId("CERTIFY_VC_SIGN_ED25519");
        dto.setKeyManagerRefId("ED25519_SIGN");
        dto.setSignatureAlgo("EdDSA");
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setMetaDataDisplay(display());
        dto.setDisplayOrder(new ArrayList<>(List.of("fullName", "gender")));
        dto.setScope("t1077_ldp_vc");
        dto.setClaims(new LinkedHashMap<>(Map.of("fullName",
                new ClaimsDTO(List.of(new ClaimsDTO.Display("Full Name", "en"))))));
        dto.setSdClaim(sdClaim);
        return dto;
    }

    private static CredentialConfigurationDTO msoMdocRequest(String sdClaim) {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setVcTemplate("test_template");
        dto.setCredentialConfigKeyId("mso-mdoc-config");
        dto.setContextURLs(new ArrayList<>());
        dto.setCredentialTypes(new ArrayList<>());
        dto.setCredentialFormat("mso_mdoc");
        dto.setDocType("org.iso.18013.5.1.T1077");
        dto.setSignatureCryptoSuite("EcdsaSecp256r1Signature2019");
        dto.setKeyManagerAppId("CERTIFY_VC_SIGN_EC_R1");
        dto.setKeyManagerRefId("EC_SECP256R1_SIGN");
        dto.setCryptographicBindingMethodsSupported(new ArrayList<>(List.of("cose_key")));
        dto.setMetaDataDisplay(display());
        dto.setDisplayOrder(new ArrayList<>(List.of("org.iso.18013.5.1.mDL~family_name")));
        dto.setScope("t1077_mso_mdoc");
        Map<String, Map<String, ClaimsDisplayFieldsConfigDTO>> claims = new LinkedHashMap<>();
        claims.put("org.iso.18013.5.1", new LinkedHashMap<>(Map.of("family_name", claimDisplay("Family Name"))));
        dto.setMsoMdocClaims(claims);
        dto.setSdClaim(sdClaim);
        return dto;
    }

    /**
     * The dc+sd-jwt configuration as a previous add stored it: built by the real mapper, with the three
     * metadata attributes the add path fills in, and every collection mutable as Hibernate would load it.
     */
    private static CredentialConfig storedSdJwtConfig() {
        CredentialConfig stored = new CredentialConfigMapperImpl().toEntity(sdJwtRequest(STORED_SD_CLAIM));
        stored.setConfigId(UUID.randomUUID().toString());
        stored.setStatus(Constants.ACTIVE);
        stored.setCryptographicBindingMethodsSupported(new ArrayList<>(List.of("did:jwk", "did:web")));
        stored.setCredentialSigningAlgValuesSupported(new ArrayList<>(List.of("ES256")));
        Map<String, Object> proofTypes = new LinkedHashMap<>();
        proofTypes.put("jwt", Map.of(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED,
                List.of("RS256", "PS256", "ES256", "EdDSA")));
        stored.setProofTypesSupported(proofTypes);
        return stored;
    }

    /**
     * Adding must be refused with invalid_sd_claim, and nothing saved.
     *
     * @param offendingEntry the entry the message must name in single quotes, or null for a blank entry,
     *                       which has no text to name
     */
    private void assertAddRejected(CredentialConfigurationDTO request, String offendingEntry) {
        CertifyException e = assertThrows("sdClaim <" + request.getSdClaim() + "> must be rejected on add",
                CertifyException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));
        assertInvalidSdClaim(e, request.getSdClaim(), offendingEntry);
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    private void assertAddRejected(String sdClaim, String offendingEntry) {
        assertAddRejected(sdJwtRequest(sdClaim), offendingEntry);
    }

    /** Adding must succeed: saved exactly once, with the sdClaim exactly as sent. */
    private void assertAddAccepted(CredentialConfigurationDTO request) {
        credentialConfigurationService.addCredentialConfiguration(request);

        ArgumentCaptor<CredentialConfig> saved = ArgumentCaptor.forClass(CredentialConfig.class);
        verify(credentialConfigRepository, times(1)).save(saved.capture());
        Assert.assertEquals("sdClaim must be stored as sent", request.getSdClaim(), saved.getValue().getSdClaim());
    }

    private void assertAddAccepted(String sdClaim) {
        assertAddAccepted(sdJwtRequest(sdClaim));
    }

    /** Updating the stored dc+sd-jwt configuration to this sdClaim must be refused, and nothing saved. */
    private void assertUpdateRejected(String sdClaim, String offendingEntry) {
        // Lenient: the fix may check the request before it looks the stored configuration up.
        lenient().when(credentialConfigRepository.findByCredentialConfigKeyId(SD_JWT_KEY_ID))
                .thenReturn(Optional.of(storedSdJwtConfig()));

        CertifyException e = assertThrows("sdClaim <" + sdClaim + "> must be rejected on update",
                CertifyException.class,
                () -> credentialConfigurationService.updateCredentialConfiguration(SD_JWT_KEY_ID, sdJwtRequest(sdClaim)));
        assertInvalidSdClaim(e, sdClaim, offendingEntry);
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    private static void assertInvalidSdClaim(CertifyException e, String sdClaim, String offendingEntry) {
        Assert.assertEquals("errorCode for sdClaim <" + sdClaim + "> (message: " + e.getMessage() + ")",
                INVALID_SD_CLAIM, e.getErrorCode());
        if (offendingEntry != null) {
            Assert.assertTrue("message must name '" + offendingEntry + "' but was: " + e.getMessage(),
                    e.getMessage() != null && e.getMessage().contains("'" + offendingEntry + "'"));
        }
    }


    /** sd_claims set to a random value. */
    @Test
    public void should_throwCertifyException_when_sdClaimIsRandomValue() {
        assertAddRejected("abcdef", "abcdef");
    }

    @Test
    public void should_throwCertifyException_when_sdClaimIsFieldNameWithoutRoot() {
        assertAddRejected("fullName", "fullName");
    }

    @Test
    public void should_throwCertifyException_when_sdClaimHasLeadingDotWithoutRoot() {
        assertAddRejected(".fullName", ".fullName");
    }

    @Test
    public void should_throwCertifyException_when_sdClaimIsDottedButUnrooted() {
        assertAddRejected("credentialSubject.name", "credentialSubject.name");
    }

    @Test
    public void should_throwCertifyException_when_sdClaimUsesRecursiveDescent() {
        assertAddRejected("$..fullName", "$..fullName");
    }

    @Test
    public void should_throwCertifyException_when_sdClaimHasZeroPaddedIndex() {
        assertAddRejected("$.phoneNumbers[01]", "$.phoneNumbers[01]");
    }

    @Test
    public void should_throwCertifyException_when_sdClaimHasNonNumericIndex() {
        assertAddRejected("$.phoneNumbers[x]", "$.phoneNumbers[x]");
    }

    @Test
    public void should_throwCertifyException_when_sdClaimHasTrailingDot() {
        assertAddRejected("$.address.", "$.address.");
    }

    @Test
    public void should_throwCertifyException_when_sdClaimHasUnbalancedBracket() {
        assertAddRejected("$.address[", "$.address[");
    }

    @Test
    public void should_throwCertifyException_when_sdClaimHasTrailingJunkAfterSegment() {
        assertAddRejected("$[0]x", "$[0]x");
    }

    // ================================================================== add: blank entries

    /** An empty value is not "no selective disclosure" - that is an omitted sdClaim. */
    @Test
    public void should_throwCertifyException_when_sdClaimIsEmptyString() {
        assertAddRejected("", null);
    }

    @Test
    public void should_throwCertifyException_when_sdClaimIsWhitespaceOnly() {
        assertAddRejected("   ", null);
    }

    /** split(",") drops trailing empties: "," splits to a zero-length array, so allMatch is vacuously true. */
    @Test
    public void should_throwCertifyException_when_sdClaimIsSingleSeparator() {
        assertAddRejected(",", null);
    }

    @Test
    public void should_throwCertifyException_when_sdClaimIsSeparatorsOnly() {
        assertAddRejected(",,", null);
    }

    @Test
    public void should_throwCertifyException_when_sdClaimHasEmptyEntryBetweenPaths() {
        assertAddRejected("$.fullName,,$.gender", null);
    }

    @Test
    public void should_throwCertifyException_when_sdClaimHasWhitespaceEntryBetweenPaths() {
        assertAddRejected("$.fullName, ,$.gender", null);
    }

    /** split(",") would leave one valid path here, hiding the trailing blank entry. */
    @Test
    public void should_throwCertifyException_when_sdClaimHasTrailingSeparator() {
        assertAddRejected("$.fullName,", null);
    }

    @Test
    public void should_throwCertifyException_when_sdClaimHasTwoTrailingSeparators() {
        assertAddRejected("$.fullName,,", null);
    }

    @Test
    public void should_throwCertifyException_when_sdClaimHasLeadingSeparator() {
        assertAddRejected(",$.fullName", null);
    }

    @Test
    public void should_nameTheInvalidEntry_when_sdClaimHasValidThenInvalidEntry() {
        assertAddRejected("$.fullName,abcdef", "abcdef");
    }

    @Test
    public void should_nameTheInvalidEntry_when_sdClaimHasInvalidEntryLast() {
        assertAddRejected("$.fullName, $.gender, $.address[x]", "$.address[x]");
    }

    @Test
    public void should_nameOnlyTheFirstInvalidEntry_when_sdClaimHasTwoInvalidEntries() {
        CredentialConfigurationDTO request = sdJwtRequest("$.ok, firstBad, secondBad");
        CertifyException e = assertThrows("sdClaim <" + request.getSdClaim() + "> must be rejected on add",
                CertifyException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));
        assertInvalidSdClaim(e, request.getSdClaim(), "firstBad");
        Assert.assertFalse("message must stop at the first offender but was: " + e.getMessage(),
                e.getMessage().contains("secondBad"));
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    @Test
    public void should_allowCredentialConfiguration_when_sdClaimIsOmitted() {
        assertAddAccepted((String) null);
    }

    @Test
    public void should_allowCredentialConfiguration_when_sdClaimIsSinglePath() {
        assertAddAccepted("$.fullName");
    }

    @Test
    public void should_allowCredentialConfiguration_when_sdClaimHasTwoPaths() {
        assertAddAccepted("$.fullName,$.gender");
    }

    /** isPathSyntaxValid trims, and VC fetch accepts this today, so it must stay valid. */
    @Test
    public void should_allowCredentialConfiguration_when_sdClaimHasSpaceAfterSeparator() {
        assertAddAccepted("$.fullName, $.gender");
    }

    @Test
    public void should_allowCredentialConfiguration_when_sdClaimIsNestedPath() {
        assertAddAccepted("$.address.region");
    }

    @Test
    public void should_allowCredentialConfiguration_when_sdClaimHasArrayIndex() {
        assertAddAccepted("$.phoneNumbers[0]");
    }

    @Test
    public void should_allowCredentialConfiguration_when_sdClaimHasArrayWildcard() {
        assertAddAccepted("$.phoneNumbers[*]");
    }

    @Test
    public void should_allowCredentialConfiguration_when_sdClaimHasObjectWildcard() {
        assertAddAccepted("$.address.*");
    }

    /** Decided: the root alone is a well formed path, so it is accepted. */
    @Test
    public void should_allowCredentialConfiguration_when_sdClaimIsRootOnly() {
        assertAddAccepted("$");
    }

    @Test
    public void should_allowCredentialConfiguration_when_sdClaimRepeatsAPath() {
        assertAddAccepted("$.fullName,$.fullName");
    }

    /** Scope guard: well formed but not in the template. Needs credential data, so it stays at VC fetch. */
    @Test
    public void should_allowCredentialConfiguration_when_sdClaimPathIsNotInTemplate() {
        assertAddAccepted("$.favouriteColour");
    }

    /** Scope guard: well formed but the wrong shape (fullName is a string). Stays at VC fetch. */
    @Test
    public void should_allowCredentialConfiguration_when_sdClaimPathHasWrongShapeForCredential() {
        assertAddAccepted("$.fullName[*]");
    }

    /** sdClaim is only read for dc+sd-jwt, so other formats are not checked for it. */
    @Test
    public void should_allowCredentialConfiguration_when_ldpVcSdClaimIsInvalid() {
        assertAddAccepted(ldpVcRequest("abcdef"));
    }

    @Test
    public void should_allowCredentialConfiguration_when_msoMdocSdClaimIsInvalid() {
        assertAddAccepted(msoMdocRequest("abcdef"));
    }

    @Test
    public void should_allowCredentialConfiguration_when_ldpVcSdClaimIsValid() {
        assertAddAccepted(ldpVcRequest("$.fullName, $.address.region"));
    }

    /** Wrong in two ways; the dc+sd-jwt mandatory fields are checked before sdClaim. */
    @Test
    public void should_reportMissingMandatoryFields_when_sdClaimIsAlsoInvalid() {
        CredentialConfigurationDTO request = sdJwtRequest("abcdef");
        request.setSdJwtVct(null);
        CertifyException e = assertThrows(CertifyException.class,
                () -> credentialConfigurationService.addCredentialConfiguration(request));
        Assert.assertEquals(ErrorConstants.DC_SD_JWT_MANDATORY_FIELDS_MISSING, e.getErrorCode());
        verify(credentialConfigRepository, never()).save(any(CredentialConfig.class));
    }

    @Test
    public void should_throwCertifyException_when_updatedSdClaimIsRandomValue() {
        assertUpdateRejected("abcdef", "abcdef");
    }

    @Test
    public void should_throwCertifyException_when_updatedSdClaimHasEmptyEntryBetweenPaths() {
        assertUpdateRejected("$.fullName,,$.gender", null);
    }

    @Test
    public void should_throwCertifyException_when_updatedSdClaimHasTrailingSeparator() {
        assertUpdateRejected("$.fullName,", null);
    }

    @Test
    public void should_saveNewSdClaim_when_updatedSdClaimIsValid() {
        when(credentialConfigRepository.findByCredentialConfigKeyId(SD_JWT_KEY_ID))
                .thenReturn(Optional.of(storedSdJwtConfig()));

        credentialConfigurationService.updateCredentialConfiguration(SD_JWT_KEY_ID,
                sdJwtRequest("$.gender, $.address.postalCode"));

        ArgumentCaptor<CredentialConfig> saved = ArgumentCaptor.forClass(CredentialConfig.class);
        verify(credentialConfigRepository, times(1)).save(saved.capture());
        Assert.assertEquals("$.gender, $.address.postalCode", saved.getValue().getSdClaim());
    }

    @Test
    public void should_clearStoredSdClaim_when_updateOmitsSdClaim() {
        when(credentialConfigRepository.findByCredentialConfigKeyId(SD_JWT_KEY_ID))
                .thenReturn(Optional.of(storedSdJwtConfig()));

        credentialConfigurationService.updateCredentialConfiguration(SD_JWT_KEY_ID, sdJwtRequest(null));

        ArgumentCaptor<CredentialConfig> saved = ArgumentCaptor.forClass(CredentialConfig.class);
        verify(credentialConfigRepository, times(1)).save(saved.capture());
        Assert.assertNull("stored sdClaim", saved.getValue().getSdClaim());
    }
}
