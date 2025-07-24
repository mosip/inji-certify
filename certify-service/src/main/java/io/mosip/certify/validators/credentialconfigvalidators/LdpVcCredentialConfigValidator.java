package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;

import java.util.Optional;

public class LdpVcCredentialConfigValidator {
    public static boolean isValidCheck(CredentialConfig credentialConfig) {
        return credentialConfig.getContext() != null && !credentialConfig.getContext().isEmpty()
                && credentialConfig.getCredentialType() != null && !credentialConfig.getCredentialType().isEmpty()
                && credentialConfig.getSignatureCryptoSuite() != null && !credentialConfig.getSignatureCryptoSuite().isEmpty()
                && credentialConfig.getDocType() == null && credentialConfig.getSdJwtVct() == null
                && credentialConfig.getMsoMdocClaims() == null && credentialConfig.getSdJwtClaims() == null;
    }

    public static boolean isConfigAlreadyPresent(CredentialConfig credentialConfig,
                                        CredentialConfigRepository credentialConfigRepository) {
        Optional<CredentialConfig> optional =
                credentialConfigRepository.findByCredentialFormatAndCredentialTypeAndContext(
                credentialConfig.getCredentialFormat(),
                credentialConfig.getCredentialType(),
                credentialConfig.getContext());

        return optional.isPresent();
    }
}