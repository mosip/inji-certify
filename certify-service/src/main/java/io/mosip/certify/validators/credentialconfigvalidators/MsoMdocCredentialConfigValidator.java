package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;

import java.util.Optional;

public class MsoMdocCredentialConfigValidator {
    public static boolean isValidCheck(CredentialConfig credentialConfig) {
        return credentialConfig.getDocType() != null && !credentialConfig.getDocType().isEmpty()
                && credentialConfig.getSignatureCryptoSuite() != null && !credentialConfig.getSignatureCryptoSuite().isEmpty()
                && credentialConfig.getCredentialType() == null && credentialConfig.getContext() == null
                && credentialConfig.getSdJwtVct() == null && credentialConfig.getCredentialSubject() == null
                && credentialConfig.getSdJwtClaims() == null;
    }

    public static boolean isConfigAlreadyPresent(CredentialConfig credentialConfig,
                                                 CredentialConfigRepository credentialConfigRepository) {
        Optional<CredentialConfig> optional =
                credentialConfigRepository.findByCredentialFormatAndDocType(
                        credentialConfig.getCredentialFormat(),
                        credentialConfig.getDocType());

        return optional.isPresent();
    }
}
