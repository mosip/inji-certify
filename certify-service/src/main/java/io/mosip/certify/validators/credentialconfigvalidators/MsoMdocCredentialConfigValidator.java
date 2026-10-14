package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;

import java.util.Optional;

public class MsoMdocCredentialConfigValidator {

    /**
     * An mdoc's issuerAuth is signed with signatureAlgo alone, so that is mandatory. signatureCryptoSuite
     * plays no part in signing an mdoc and is not required; a request that sends one is rejected by the
     * service as an invalid request.
     */
    public static boolean isValidCheck(CredentialConfigurationDTO credentialConfig) {
        return credentialConfig.getDocType() != null && !credentialConfig.getDocType().isEmpty()
                && credentialConfig.getSignatureAlgo() != null && !credentialConfig.getSignatureAlgo().isEmpty()
                && (credentialConfig.getCredentialTypes() == null || credentialConfig.getCredentialTypes().isEmpty()) && (credentialConfig.getContextURLs() == null || credentialConfig.getContextURLs().isEmpty())
                && credentialConfig.getSdJwtVct() == null && credentialConfig.getClaims() == null
                && credentialConfig.getSdJwtClaims() == null;
    }

    public static boolean isConfigAlreadyPresent(CredentialConfigurationDTO credentialConfig,
                                                 CredentialConfigRepository credentialConfigRepository) {
        Optional<CredentialConfig> optional =
                credentialConfigRepository.findByCredentialFormatAndDocType(
                        credentialConfig.getCredentialFormat(),
                        credentialConfig.getDocType());

        return optional.isPresent();
    }
}