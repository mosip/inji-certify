package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;

import java.util.Optional;

public class SdJwtCredentialConfigValidator {
    public static boolean isValidCheck(CredentialConfig credentialConfig) {
        return credentialConfig.getSdJwtVct() != null && !credentialConfig.getSdJwtVct().isEmpty()
                && credentialConfig.getCredentialType() == null && credentialConfig.getContext() == null
                && credentialConfig.getDocType() == null && credentialConfig.getCredentialSubject() == null;
    }

    public static boolean isConfigAlreadyPresent(CredentialConfig credentialConfig,
                                                 CredentialConfigRepository credentialConfigRepository) {
        Optional<CredentialConfig> optional =
                credentialConfigRepository.findByCredentialFormatAndSdJwtVct(
                        credentialConfig.getCredentialFormat(),
                        credentialConfig.getSdJwtVct());

        return optional.isPresent();
    }
}
