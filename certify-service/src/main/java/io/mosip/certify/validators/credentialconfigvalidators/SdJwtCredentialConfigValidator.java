package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;

import java.util.Optional;

public class SdJwtCredentialConfigValidator {
    /**
     * signatureAlgo is mandatory in DataProvider mode, where Certify signs the credential. In VCIssuance
     * mode the plugin signs it, so signatureAlgo is optional.
     */
    public static boolean isValidCheck(CredentialConfigurationDTO credentialConfig, String pluginMode) {
        return credentialConfig.getSdJwtVct() != null && !credentialConfig.getSdJwtVct().isEmpty()
                && (!"DataProvider".equals(pluginMode) || (credentialConfig.getSignatureAlgo() != null && !credentialConfig.getSignatureAlgo().isEmpty()))
                && (credentialConfig.getCredentialTypes() == null || credentialConfig.getCredentialTypes().isEmpty()) && (credentialConfig.getContextURLs() == null || credentialConfig.getContextURLs().isEmpty())
                && credentialConfig.getDocType() == null && credentialConfig.getClaims() == null &&
                credentialConfig.getMsoMdocClaims() == null && credentialConfig.getSignatureCryptoSuite() == null;
    }

    public static boolean isConfigAlreadyPresent(CredentialConfigurationDTO credentialConfig,
                                                 CredentialConfigRepository credentialConfigRepository) {
        Optional<CredentialConfig> optional =
                credentialConfigRepository.findByCredentialFormatAndSdJwtVct(
                        credentialConfig.getCredentialFormat(),
                        credentialConfig.getSdJwtVct());

        return optional.isPresent();
    }
}