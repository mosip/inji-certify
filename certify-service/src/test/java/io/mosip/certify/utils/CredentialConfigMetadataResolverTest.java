package io.mosip.certify.utils;

import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.entity.CredentialConfig;
import org.junit.Assert;
import org.junit.Test;

import java.util.List;

/**
 * Covers what a configuration advertises in credential_signing_alg_values_supported, which is read from
 * the configuration alone and never from the deployment configuration.
 */
public class CredentialConfigMetadataResolverTest {

    @Test
    public void should_advertiseCryptoSuite_when_formatIsLdpVc() {
        CredentialConfig config = config(VCFormats.LDP_VC, "eddsa-rdfc-2022", "EdDSA");

        Assert.assertEquals(List.of("eddsa-rdfc-2022"), CredentialConfigMetadataResolver.resolveAdvertisedSigningAlgs(config));
    }

    @Test
    public void should_advertiseSignatureAlgo_when_ldpVcHasNoCryptoSuite() {
        CredentialConfig config = config(VCFormats.LDP_VC, null, "ES256");

        Assert.assertEquals(List.of("ES256"), CredentialConfigMetadataResolver.resolveAdvertisedSigningAlgs(config));
    }

    @Test
    public void should_advertiseSignatureAlgo_when_formatIsDcSdJwt() {
        CredentialConfig config = config(VCFormats.DC_SD_JWT, null, "ES256");

        Assert.assertEquals(List.of("ES256"), CredentialConfigMetadataResolver.resolveAdvertisedSigningAlgs(config));
    }

    /**
     * A configuration stored before mso_mdoc ignored the crypto suite still advertises its signatureAlgo.
     */
    @Test
    public void should_advertiseSignatureAlgo_when_formatIsMsoMdocWithStoredCryptoSuite() {
        CredentialConfig config = config(VCFormats.MSO_MDOC, "EcdsaSecp256r1Signature2019", "ES256");

        Assert.assertEquals(List.of("ES256"), CredentialConfigMetadataResolver.resolveAdvertisedSigningAlgs(config));
    }

    /**
     * The value advertised is the configuration's own, whatever was stored for the attribute earlier, so an
     * existing configuration needs no re-submission.
     */
    @Test
    public void should_ignoreStoredSigningAlgs_when_resolvingAdvertisedValue() {
        CredentialConfig config = config(VCFormats.DC_SD_JWT, null, "EdDSA");
        config.setCredentialSigningAlgValuesSupported(List.of("RS256", "ES256"));

        Assert.assertEquals(List.of("EdDSA"), CredentialConfigMetadataResolver.resolveAdvertisedSigningAlgs(config));
    }

    @Test
    public void should_advertiseNothing_when_signatureAlgoIsMissing() {
        CredentialConfig config = config(VCFormats.DC_SD_JWT, null, null);

        Assert.assertTrue(CredentialConfigMetadataResolver.resolveAdvertisedSigningAlgs(config).isEmpty());
    }

    private static CredentialConfig config(String format, String signatureCryptoSuite, String signatureAlgo) {
        CredentialConfig config = new CredentialConfig();
        config.setCredentialFormat(format);
        config.setSignatureCryptoSuite(signatureCryptoSuite);
        config.setSignatureAlgo(signatureAlgo);
        return config;
    }
}
