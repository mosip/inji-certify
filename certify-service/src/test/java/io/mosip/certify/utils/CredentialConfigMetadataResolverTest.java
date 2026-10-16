package io.mosip.certify.utils;

import org.junit.Assert;
import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertThrows;

/**
 * Covers reading mosip.certify.credential-config.credential-signing-alg-values-supported, which must be
 * grouped by credential format.
 */
public class CredentialConfigMetadataResolverTest {

    /**
     * The earlier shape, keyed by crypto suite only, is no longer read.
     */
    @Test
    public void should_failStartup_when_propertyIsKeyedByCryptoSuite() {
        Map<String, Object> declared = new LinkedHashMap<>();
        declared.put("Ed25519Signature2020", List.of("EdDSA"));
        declared.put("EcdsaSecp256r1Signature2019", List.of("ES256"));

        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> CredentialConfigMetadataResolver.parseDeclaredSigningAlgs(declared));

        Assert.assertTrue(exception.getMessage().contains("must be grouped by credential format"));
    }

    @Test
    public void should_splitSuitesAndFormats_when_propertyIsGroupedByFormat() {
        Map<String, Object> ldpVcSuites = new LinkedHashMap<>();
        ldpVcSuites.put("Ed25519Signature2020", List.of("EdDSA"));
        ldpVcSuites.put("eddsa-rdfc-2022", List.of("EdDSA"));
        Map<String, Object> declared = new LinkedHashMap<>();
        declared.put("ldp_vc", ldpVcSuites);
        declared.put("mso_mdoc", List.of("ES256"));
        declared.put("dc+sd-jwt", List.of("ES256", "EdDSA"));

        CredentialConfigMetadataResolver.DeclaredSigningAlgs result =
                CredentialConfigMetadataResolver.parseDeclaredSigningAlgs(declared);

        Assert.assertEquals(Map.of("Ed25519Signature2020", List.of("EdDSA"), "eddsa-rdfc-2022", List.of("EdDSA")),
                result.byCryptoSuite());
        Assert.assertEquals(Map.of("mso_mdoc", List.of("ES256"), "dc+sd-jwt", List.of("ES256", "EdDSA")),
                result.byFormat());
    }

    /**
     * The property need not declare every format; one it leaves out has no algorithms declared.
     */
    @Test
    public void should_declareOnlyTheGivenFormats_when_propertyOmitsSome() {
        Map<String, Object> declared = new LinkedHashMap<>();
        declared.put("ldp_vc", Map.of("Ed25519Signature2020", List.of("EdDSA")));

        CredentialConfigMetadataResolver.DeclaredSigningAlgs result =
                CredentialConfigMetadataResolver.parseDeclaredSigningAlgs(declared);

        Assert.assertEquals(Map.of("Ed25519Signature2020", List.of("EdDSA")), result.byCryptoSuite());
        Assert.assertTrue(result.byFormat().isEmpty());
    }

    /**
     * A crypto suite placed beside the formats rather than under ldp_vc fails at startup.
     */
    @Test
    public void should_failStartup_when_propertyHasAKeyThatIsNotAFormat() {
        Map<String, Object> declared = new LinkedHashMap<>();
        declared.put("mso_mdoc", List.of("ES256"));
        declared.put("Ed25519Signature2020", List.of("EdDSA"));

        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> CredentialConfigMetadataResolver.parseDeclaredSigningAlgs(declared));

        Assert.assertTrue(exception.getMessage().contains("Ed25519Signature2020 is not a credential format"));
    }

    @Test
    public void should_failStartup_when_ldpVcIsNotASuiteMap() {
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> CredentialConfigMetadataResolver.parseDeclaredSigningAlgs(Map.of("ldp_vc", List.of("EdDSA"))));

        Assert.assertTrue(exception.getMessage().contains("must map each crypto suite to its algorithms"));
    }

    @Test
    public void should_failStartup_when_formatIsNotGivenAList() {
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> CredentialConfigMetadataResolver.parseDeclaredSigningAlgs(Map.of("mso_mdoc", "ES256")));

        Assert.assertTrue(exception.getMessage().contains("mso_mdoc must be a list of algorithms"));
    }

    @Test
    public void should_returnEmptyLookups_when_propertyIsAbsent() {
        CredentialConfigMetadataResolver.DeclaredSigningAlgs result =
                CredentialConfigMetadataResolver.parseDeclaredSigningAlgs(null);

        Assert.assertTrue(result.byCryptoSuite().isEmpty());
        Assert.assertTrue(result.byFormat().isEmpty());
    }
}
