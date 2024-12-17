/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.api.spi.*;
import io.mosip.certify.api.util.Action;
import io.mosip.certify.api.util.ActionStatus;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.CredentialMetadata;
import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.core.dto.CredentialResponse;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.dto.VCIssuanceTransaction;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.exception.NotAuthenticatedException;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.core.util.AuditHelper;
import io.mosip.certify.core.util.SecurityHelperService;
import io.mosip.certify.services.spi.DataProviderPlugin;
import io.mosip.certify.services.spi.VCFormatter;
import io.mosip.certify.services.spi.VCSigner;
import io.mosip.certify.services.validators.CredentialRequestValidator;
import io.mosip.certify.exception.InvalidNonceException;
import io.mosip.certify.proof.ProofValidator;
import io.mosip.certify.proof.ProofValidatorFactory;
import io.mosip.certify.services.templating.VelocityTemplatingConstants;
import io.mosip.certify.utils.CredentialUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;

@Slf4j
@Service
@ConditionalOnProperty(value = "mosip.certify.issuer", havingValue = "CertifyIssuer")
public class CertifyIssuanceServiceImpl implements VCIssuanceService {

    @Value("#{${mosip.certify.key-values}}")
    private LinkedHashMap<String, LinkedHashMap<String, Object>> issuerMetadata;

    @Value("${mosip.certify.cnonce-expire-seconds:300}")
    private int cNonceExpireSeconds;

    @Autowired
    private ParsedAccessToken parsedAccessToken;

    @Autowired
    private VCFormatter vcFormatter;

    @Autowired
    private VCSigner vcSigner;

    @Autowired
    private DataProviderPlugin dataProviderPlugin;

    @Value("${mosip.certify.data-provider-plugin.issuer-uri}")
    private String issuerURI;

    @Value("${mosip.certify.data-provider-plugin.rendering-template-id:}")
    private String svgTemplateId;

    @Autowired
    private ProofValidatorFactory proofValidatorFactory;

    @Autowired
    private VCICacheService vciCacheService;

    @Autowired
    private SecurityHelperService securityHelperService;

    @Autowired
    private AuditPlugin auditWrapper;

    @Override
    public CredentialResponse getCredential(CredentialRequest credentialRequest) {
        // 1. Credential Request validation
        boolean isValidCredentialRequest = CredentialRequestValidator.isValid(credentialRequest);
        if(!isValidCredentialRequest) {
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
        }

        if(!parsedAccessToken.isActive())
            throw new NotAuthenticatedException();
        // 2. Scope Validation
        String scopeClaim = (String) parsedAccessToken.getClaims().getOrDefault("scope", "");
        CredentialMetadata credentialMetadata = null;
        for(String scope : scopeClaim.split(Constants.SPACE)) {
            Optional<CredentialMetadata> result = getScopeCredentialMapping(scope, credentialRequest.getFormat());
            if(result.isPresent()) {
                credentialMetadata = result.get(); //considering only first credential scope
                break;
            }
        }

        if(credentialMetadata == null) {
            log.error("No credential mapping found for the provided scope {}", scopeClaim);
            throw new CertifyException(ErrorConstants.INVALID_SCOPE);
        }

        // 3. Proof Validation
        ProofValidator proofValidator = proofValidatorFactory.getProofValidator(credentialRequest.getProof().getProof_type());
        if(!proofValidator.validate((String)parsedAccessToken.getClaims().get(Constants.CLIENT_ID), getValidClientNonce(),
                credentialRequest.getProof())) {
            throw new CertifyException(ErrorConstants.INVALID_PROOF);
        }

        // 4. Get VC from configured plugin implementation
        VCResult<?> vcResult = getVerifiableCredential(credentialRequest, credentialMetadata,
                proofValidator.getKeyMaterial(credentialRequest.getProof()));

        auditWrapper.logAudit(Action.VC_ISSUANCE, ActionStatus.SUCCESS,
                AuditHelper.buildAuditDto(parsedAccessToken.getAccessTokenHash(), "accessTokenHash"), null);
        return getCredentialResponse(credentialRequest.getFormat(), vcResult);
    }

    @Override
    public Map<String, Object> getCredentialIssuerMetadata(String version) {
       if(issuerMetadata.containsKey(version)) {
           return issuerMetadata.get(version);
       } else if(version != null && version.equals("vd12")) {
           Map<String, Object> vd12IssuerMetadata = convertLatestToVd12(issuerMetadata.get("latest"));
           return vd12IssuerMetadata;
       } else if(version != null && version.equals("vd11")) {
           Map<String, Object> vd11IssuerMetadata = convertLatestToVd11(issuerMetadata.get("latest"));
           return vd11IssuerMetadata;
       }
       throw new InvalidRequestException(ErrorConstants.UNSUPPORTED_OPENID_VERSION);
    }

    private Map<String, Object> convertLatestToVd11(LinkedHashMap<String, Object> vciMetadata) {
        // Create a list to hold the transformed credentials
        List<Map<String, Object>> credentialsList = new ArrayList<>();

        // Check if the original config contains 'credential_configurations_supported'
        if (vciMetadata.containsKey("credential_configurations_supported")) {
            // Cast the value to a Map
            Map<String, Object> originalCredentials =
                    (Map<String, Object>) vciMetadata.get("credential_configurations_supported");

            // Iterate through each credential
            for (Map.Entry<String, Object> entry : originalCredentials.entrySet()) {
                // Cast the credential configuration
                Map<String, Object> credConfig = (Map<String, Object>) entry.getValue();

                // Create a new transformed credential configuration
                Map<String, Object> transformedCredential = new HashMap<>(credConfig);

                // Add 'id' field with the original key
                transformedCredential.put("id", entry.getKey());

                // Rename 'credential_signing_alg_values_supported' to 'cryptographic_suites_supported'
                if (transformedCredential.containsKey("credential_signing_alg_values_supported")) {
                    transformedCredential.put("cryptographic_suites_supported",
                            transformedCredential.remove("credential_signing_alg_values_supported"));
                }

                // Modify proof_types_supported
                if (transformedCredential.containsKey("proof_types_supported")) {
                    Map<String, Object> proofTypes = (Map<String, Object>) transformedCredential.get("proof_types_supported");
                    transformedCredential.put("proof_types_supported", proofTypes.keySet());
                }

                if(transformedCredential.containsKey("display")) {
                    List<Map<String, Object>> displayMapList = new ArrayList<>((List<Map<String, Object>>)transformedCredential.get("display"));
                    List<Map<String, Object>> newDisplayMapList = new ArrayList<>();
                    for(Map<String, Object> map : displayMapList) {
                        Map<String, Object> displayMap = new HashMap<>(map);
                        displayMap.remove("background_image");
                        newDisplayMapList.add(displayMap);
                    }
                    transformedCredential.put("display", newDisplayMapList);
                }

                // Remove 'order' if it exists
                transformedCredential.remove("order");

                // Add the transformed credential to the list
                credentialsList.add(transformedCredential);
            }

            // Set the transformed credentials in the new configuration
            vciMetadata.put("credentials_supported", credentialsList);
        }

        vciMetadata.remove("credential_configurations_supported");
        vciMetadata.remove("authorization_servers");
        vciMetadata.remove("display");
        String endpoint = (String)vciMetadata.get("credential_endpoint");
        int issuanceIndex = endpoint.indexOf("issuance/");
        String newEndPoint = endpoint.substring(0, issuanceIndex+9);
        vciMetadata.put("credential_endpoint", newEndPoint + "vd11/credential");
        return vciMetadata;
    }

    private Map<String, Object> convertLatestToVd12(LinkedHashMap<String, Object> vciMetadata) {
        // Create a new map to store the transformed configuration
        if(vciMetadata.containsKey("credential_configurations_supported")) {
            LinkedHashMap<String, Object> supportedCredentials = (LinkedHashMap<String, Object>) vciMetadata.get("credential_configurations_supported");
            Map<String, Object> transformedMap = transformCredentialConfiguration(supportedCredentials);
            vciMetadata.put("credentials_supported", transformedMap);
        }

        vciMetadata.remove("credential_configurations_supported");
        String endpoint = (String)vciMetadata.get("credential_endpoint");
        int issuanceIndex = endpoint.indexOf("issuance/");
        String newEndPoint = endpoint.substring(0, issuanceIndex+9);
        vciMetadata.put("credential_endpoint", newEndPoint + "vd12/credential");
        return vciMetadata;
    }

    private static Map<String, Object> transformCredentialConfiguration(LinkedHashMap<String, Object> originalConfig) {
        Map<String, Object> transformedConfig = new LinkedHashMap<>();

        for (Map.Entry<String, Object> entry : originalConfig.entrySet()) {
            Map<String, Object> credentialDetails = (Map<String, Object>) entry.getValue();

            // Create a new map to store modified credential details
            Map<String, Object> transformedCredential = new LinkedHashMap<>(credentialDetails);

            // Replace 'credential_signing_alg_values_supported' with 'cryptographic_suites_supported'
            if (transformedCredential.containsKey("credential_signing_alg_values_supported")) {
                Object signingAlgs = transformedCredential.remove("credential_signing_alg_values_supported");
                transformedCredential.put("cryptographic_suites_supported", signingAlgs);
            }

            // Modify proof_types_supported
            if (transformedCredential.containsKey("proof_types_supported")) {
                Map<String, Object> proofTypes = (Map<String, Object>) transformedCredential.get("proof_types_supported");
                transformedCredential.put("proof_types_supported", proofTypes.keySet());
            }

            if(transformedCredential.containsKey("display")) {
                List<Map<String, Object>> displayMapList = new ArrayList<>((List<Map<String, Object>>)transformedCredential.get("display"));
                List<Map<String, Object>> newDisplayMapList = new ArrayList<>();
                for(Map<String, Object> map : displayMapList) {
                    Map<String, Object> displayMap = new HashMap<>(map);
                    displayMap.remove("background_image");
                    newDisplayMapList.add(displayMap);
                }
                transformedCredential.put("display", newDisplayMapList);
            }

            // Add the modified credential details to the transformed config
            transformedConfig.put(entry.getKey(), transformedCredential);
        }

        return transformedConfig;
    }

    private VCResult<?> getVerifiableCredential(CredentialRequest credentialRequest, CredentialMetadata credentialMetadata,
                                                String holderId) {
        parsedAccessToken.getClaims().put("accessTokenHash", parsedAccessToken.getAccessTokenHash());
        VCRequestDto vcRequestDto = new VCRequestDto();
        vcRequestDto.setFormat(credentialRequest.getFormat());


        VCResult<?> vcResult = null;
        switch (credentialRequest.getFormat()) {
            case "ldp_vc" :
                vcRequestDto.setContext(credentialRequest.getCredential_definition().getContext());
                vcRequestDto.setType(credentialRequest.getCredential_definition().getType());
                vcRequestDto.setCredentialSubject(credentialRequest.getCredential_definition().getCredentialSubject());
                validateLdpVcFormatRequest(credentialRequest, credentialMetadata);
                try {
                    // TODO(multitenancy): later decide which plugin out of n plugins is the correct one
                    JSONObject jsonObject = dataProviderPlugin.fetchData(parsedAccessToken.getClaims());
                    Map<String, Object> templateParams = new HashMap<>();
                    templateParams.put(VelocityTemplatingConstants.TEMPLATE_NAME, CredentialUtils.getTemplateName(vcRequestDto));
                    templateParams.put(VelocityTemplatingConstants.ISSUER_URI, issuerURI);
                    if (!StringUtils.isEmpty(svgTemplateId)) {
                        templateParams.put(VelocityTemplatingConstants.SVG_TEMPLATE, svgTemplateId);
                    }
                    String unSignedVC = vcFormatter.format(jsonObject, templateParams);
                    vcResult = vcSigner.attachSignature(unSignedVC);
                } catch(DataProviderExchangeException e) {
                    throw new CertifyException(e.getErrorCode());
                }
                break;
            default:
                throw new CertifyException(ErrorConstants.UNSUPPORTED_VC_FORMAT);
        }

        if(vcResult != null && vcResult.getCredential() != null)
            return vcResult;

        log.error("Failed to generate VC : {}", vcResult);
        auditWrapper.logAudit(Action.VC_ISSUANCE, ActionStatus.ERROR,
                AuditHelper.buildAuditDto(parsedAccessToken.getAccessTokenHash(), "accessTokenHash"), null);
        throw new CertifyException(ErrorConstants.VC_ISSUANCE_FAILED);
    }

    private CredentialResponse<?> getCredentialResponse(String format, VCResult<?> vcResult) {
        switch (format) {
            case "ldp_vc":
                CredentialResponse<JsonLDObject> ldpVcResponse = new CredentialResponse<>();
                ldpVcResponse.setCredential((JsonLDObject)vcResult.getCredential());
                return ldpVcResponse;
        }
        throw new CertifyException(ErrorConstants.UNSUPPORTED_VC_FORMAT);
    }

    private Optional<CredentialMetadata>  getScopeCredentialMapping(String scope, String format) {
        Map<String, Object> vciMetadata = getCredentialIssuerMetadata("latest");
        LinkedHashMap<String, Object> supportedCredentials = (LinkedHashMap<String, Object>) vciMetadata.get("credential_configurations_supported");
        Optional<Map.Entry<String, Object>> result = supportedCredentials.entrySet().stream()
                .filter(cm -> ((LinkedHashMap<String, Object>) cm.getValue()).get("scope").equals(scope)).findFirst();

        if(result.isPresent()) {
            LinkedHashMap<String, Object> metadata = (LinkedHashMap<String, Object>)result.get().getValue();
            CredentialMetadata credentialMetadata = new CredentialMetadata();
            credentialMetadata.setFormat((String) metadata.get("format"));
            credentialMetadata.setScope((String) metadata.get("scope"));
            credentialMetadata.setId(result.get().getKey());
            if(format.equals(VCFormats.LDP_VC)){
                LinkedHashMap<String, Object> credentialDefinition = (LinkedHashMap<String, Object>) metadata.get("credential_definition");
                credentialMetadata.setTypes((List<String>) credentialDefinition.get("type"));
            }
            return Optional.of(credentialMetadata);
        }
        return Optional.empty();
    }

    private void validateLdpVcFormatRequest(CredentialRequest credentialRequest,
                                            CredentialMetadata credentialMetadata) {
        if(!credentialRequest.getCredential_definition().getType().containsAll(credentialMetadata.getTypes()))
             throw new InvalidRequestException(ErrorConstants.UNSUPPORTED_VC_TYPE);

        //TODO need to validate Credential_definition as JsonLD document, if invalid throw exception
    }

    private String getValidClientNonce() {
        VCIssuanceTransaction transaction = vciCacheService.getVCITransaction(parsedAccessToken.getAccessTokenHash());
        //If the transaction is null, it means that VCI service never created cNonce, its authorization server issued cNonce
        String cNonce = (transaction == null) ?
                (String) parsedAccessToken.getClaims().get(Constants.C_NONCE) :
                transaction.getCNonce();
        Object nonceExpireSeconds = parsedAccessToken.getClaims().getOrDefault(Constants.C_NONCE_EXPIRES_IN, 0);
        int cNonceExpire = (transaction == null) ?
                nonceExpireSeconds instanceof Long ? (int)(long)nonceExpireSeconds : (int)nonceExpireSeconds :
                transaction.getCNonceExpireSeconds();
        long issuedEpoch = (transaction == null) ?
                ((Instant) parsedAccessToken.getClaims().getOrDefault(JwtClaimNames.IAT, Instant.MIN)).getEpochSecond():
                transaction.getCNonceIssuedEpoch();

        if( cNonce == null ||
                cNonceExpire <= 0 ||
                (issuedEpoch+cNonceExpire) < LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC) ) {
            log.error("Client Nonce not found / expired in the access token, generate new cNonce");
            transaction = createVCITransaction();
            throw new InvalidNonceException(transaction.getCNonce(), transaction.getCNonceExpireSeconds());
        }
        return cNonce;
    }

    private VCIssuanceTransaction createVCITransaction() {
        VCIssuanceTransaction transaction = new VCIssuanceTransaction();
        transaction.setCNonce(securityHelperService.generateSecureRandomString(20));
        transaction.setCNonceIssuedEpoch(LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC));
        transaction.setCNonceExpireSeconds(cNonceExpireSeconds);
        return vciCacheService.setVCITransaction(parsedAccessToken.getAccessTokenHash(), transaction);
    }
}
