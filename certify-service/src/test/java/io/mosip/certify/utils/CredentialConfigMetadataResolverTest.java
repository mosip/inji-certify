package io.mosip.certify.utils;

import org.junit.Assert;
import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertThrows;

/**
 * Covers reading mosip.certify.credential-config.credential-signing-alg-values-supported in both of its
 * shapes: keyed by crypto suite only, and grouped by credential format.
 */
public class CredentialConfigMetadataResolverTest {

    @Test
    public void should_readEverySuite_when_propertyIsKeyedByCryptoSuite() {
        Map<String, Object> declared = new LinkedHashMap<>();
        declared.put("Ed25519Signature2020", List.of("EdDSA"));
        declared.put("EcdsaSecp256r1Signature2019", List.of("ES256"));

        CredentialConfigMetadataResolver.DeclaredSigningAlgs result =
                CredentialConfigMetadataResolver.parseDeclaredSigningAlgs(declared);

        Assert.assertEquals(Map.of("Ed25519Signature2020", List.of("EdDSA"), "EcdsaSecp256r1Signature2019", List.of("ES256")),
                result.byCryptoSuite());
        Assert.assertTrue(result.byFormat().isEmpty());
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
     * A grouped property need not declare every format; one it leaves out keeps the original behaviour.
     */
    @Test
    public void should_declareOnlyTheGivenFormats_when_groupedPropertyOmitsSome() {
        Map<String, Object> declared = new LinkedHashMap<>();
        declared.put("ldp_vc", Map.of("Ed25519Signature2020", List.of("EdDSA")));

        CredentialConfigMetadataResolver.DeclaredSigningAlgs result =
                CredentialConfigMetadataResolver.parseDeclaredSigningAlgs(declared);

        Assert.assertEquals(Map.of("Ed25519Signature2020", List.of("EdDSA")), result.byCryptoSuite());
        Assert.assertTrue(result.byFormat().isEmpty());
    }

    /**
     * Mixing the two shapes is ambiguous, so it fails at startup rather than guessing.
     */
    @Test
    public void should_failStartup_when_groupedPropertyHasAKeyThatIsNotAFormat() {
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
