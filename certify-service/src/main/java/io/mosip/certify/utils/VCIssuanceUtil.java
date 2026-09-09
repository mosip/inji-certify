package io.mosip.certify.utils;

import com.nimbusds.jwt.SignedJWT;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.core.constants.*;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.api.dto.VCResult;

import io.mosip.certify.services.VCICacheService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;

import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;

@Slf4j
public class VCIssuanceUtil {

    private VCIssuanceUtil() {
        // Private constructor to prevent instantiation
    }

    public static String validateAndGetClientNonce(VCICacheService vciCacheService,
                                                   String proof, Logger log, String nonceEndpoint) {
        boolean hasNonceEndpoint = nonceEndpoint != null && !nonceEndpoint.isEmpty();
        String proofJwtNonce = null;
        boolean proofJwtHasNonceClaim;
        try {
            SignedJWT proofJwt = SignedJWT.parse(proof);
            Map<String, Object> proofClaims = proofJwt.getJWTClaimsSet().getClaims();
            proofJwtHasNonceClaim = proofClaims.containsKey("nonce");
            if (proofJwtHasNonceClaim && hasNonceEndpoint) {
                proofJwtNonce = proofJwt.getJWTClaimsSet().getStringClaim("nonce");
                if (StringUtils.isBlank(proofJwtNonce)) {
                    log.error("Nonce claim is present in proof JWT but is blank");
                    throw new CertifyException(VCIErrorConstants.INVALID_PROOF, "Nonce claim must not be empty.");
                }
            }
        }
        catch (ParseException e) {
            // check iff specific error exists for invalid holderKey
            throw new CertifyException(VCIErrorConstants.INVALID_PROOF, "Error encountered during proof jwt parsing.");
        }

        if (proofJwtHasNonceClaim != hasNonceEndpoint) {
            if (proofJwtHasNonceClaim) {
                throw new CertifyException(
                        VCIErrorConstants.INVALID_PROOF,
                        "nonce claim is present, but issuer doesn't support nonce"
                );
            } else {
                throw new CertifyException(
                        VCIErrorConstants.INVALID_PROOF,
                        "nonce claim is missing, but issuer support nonce"
                );
            }
        }

        if (proofJwtNonce != null) {
            VCIssuanceTransaction transaction = vciCacheService.getNonceTransaction(proofJwtNonce);

            int cNonceExpire;

            if (transaction == null) {
                log.error("Nonce Transaction could not be found");
                throw new CertifyException(NonceErrorConstants.INVALID_NONCE, "c_nonce is invalid or expired");
            } else {
                cNonceExpire = transaction.getCNonceExpireSeconds();
            }

            long issuedEpoch = transaction.getCNonceIssuedEpoch();

            boolean nonceExpired = (cNonceExpire <= 0 ||
                    (issuedEpoch + cNonceExpire) < LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC));

            if (nonceExpired) {
                throw new CertifyException(NonceErrorConstants.NONCE_EXPIRED, "c_nonce is expired.");
            }

            return transaction.getCNonce();
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    public static CredentialResponse<?> getCredentialResponse(String format, List<VCResult<?>> vcResults) {
        switch (format) {
            case VCFormats.LDP_VC:
                CredentialResponse<JsonLDObject> ldpVcResponse = new CredentialResponse<>();
                List<CredentialResponse.CredentialWrapper<JsonLDObject>> ldpVcCredentials = new ArrayList<>();
                for (VCResult<?> vcResult : vcResults) {
                    CredentialResponse.CredentialWrapper<JsonLDObject> credentialWrapper = new CredentialResponse.CredentialWrapper<>();
                    credentialWrapper.setCredential((JsonLDObject) vcResult.getCredential());
                    ldpVcCredentials.add(credentialWrapper);
                }
                ldpVcResponse.setCredentials(ldpVcCredentials);
                return ldpVcResponse;

            case VCFormats.DC_SD_JWT:
            case VCFormats.MSO_MDOC:
                CredentialResponse<String> stringResponse = new CredentialResponse<>();
                List<CredentialResponse.CredentialWrapper<String>> credentials = new ArrayList<>();
                for (VCResult<?> vcResult : vcResults) {
                    CredentialResponse.CredentialWrapper<String> credentialWrapper = new CredentialResponse.CredentialWrapper<>();
                    credentialWrapper.setCredential((String) vcResult.getCredential());
                    credentials.add(credentialWrapper);
                }
                stringResponse.setCredentials(credentials);
                return stringResponse;

            default:
                throw new CertifyException(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT, " Input format " + format);
        }
    }

    public static Optional<CredentialConfigurationSupported> getScopeCredentialMapping(
            String scope,
            String credentialConfigId,
            CredentialIssuerMetadataDTO credentialIssuerMetadataDTO) {

        Map<String, CredentialConfigurationSupportedDTO> supportedCredentials =
                credentialIssuerMetadataDTO.getCredentialConfigurationSupportedDTO();

        CredentialConfigurationSupportedDTO credentialConfig = supportedCredentials.get(credentialConfigId);
        if(credentialConfig == null) {
            throw new CertifyException(VCIErrorConstants.INVALID_CREDENTIAL_REQUEST,
                    "No credential configuration found for credential_configuration_id");
        }

        if(!Objects.equals(scope, credentialConfig.getScope())){
            return Optional.empty();
        }

        CredentialConfigurationSupported credentialConfigurationSupported = new CredentialConfigurationSupported();
        credentialConfigurationSupported.setFormat(credentialConfig.getFormat());
        credentialConfigurationSupported.setScope(credentialConfig.getScope());
        credentialConfigurationSupported.setId(credentialConfigId);
        credentialConfigurationSupported.setProofTypesSupported(credentialConfig.getProofTypesSupported());
        if (credentialConfig.getCredentialDefinition() != null) {
            credentialConfigurationSupported.setTypes(credentialConfig.getCredentialDefinition().getType());
            credentialConfigurationSupported.setContext(credentialConfig.getCredentialDefinition().getContext());
        }

        if(credentialConfig.getFormat().equals(VCFormats.DC_SD_JWT)) {
            credentialConfigurationSupported.setVct(credentialConfig.getVct());
        } else if(credentialConfig.getFormat().equals(VCFormats.MSO_MDOC)) {
            credentialConfigurationSupported.setDocType(credentialConfig.getDocType());
        }


        return Optional.of(credentialConfigurationSupported);
    }
}