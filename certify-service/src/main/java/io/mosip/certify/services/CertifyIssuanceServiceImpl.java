/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import com.nimbusds.jose.JWSAlgorithm;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.api.spi.*;
import io.mosip.certify.api.util.Action;
import io.mosip.certify.api.util.ActionStatus;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.constants.SignatureAlg;
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
import io.mosip.certify.core.validators.CredentialRequestValidatorFactory;
import io.mosip.certify.exception.InvalidNonceException;
import io.mosip.certify.proof.ProofValidator;
import io.mosip.certify.proof.ProofValidatorFactory;
import io.mosip.certify.services.templating.VelocityTemplatingConstants;
import io.mosip.certify.utils.CredentialUtils;
import lombok.extern.slf4j.Slf4j;
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
    private DataProviderPlugin dataModelService;

    @Value("${mosip.certify.issuer.pub.key}")
    private String hostedKey;

    @Value("${mosip.certify.issuer.uri}")
    private String issuerURI;

    @Autowired
    private ProofValidatorFactory proofValidatorFactory;

    @Autowired
    private VCICacheService vciCacheService;

    @Autowired
    private SecurityHelperService securityHelperService;

    @Value("${mosip.certify.issuer.vc-sign-algo:Ed25519Signature2018}")
    private String VCSignAlgo;

    @Value("${mosip.certify.issuer.svg.template.id}")
    private String svg;

    @Autowired
    private AuditPlugin auditWrapper;

    @Override
    public CredentialResponse getCredential(CredentialRequest credentialRequest) {
        // 1. Credential Request validation
        boolean isValidCredentialRequest = new CredentialRequestValidatorFactory().isValid(credentialRequest);
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
       if(issuerMetadata.containsKey(version))
           return issuerMetadata.get(version);
       throw new InvalidRequestException(ErrorConstants.UNSUPPORTED_OPENID_VERSION);
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
                    JSONObject jsonObject = dataModelService.fetchData(parsedAccessToken.getClaims());
                    Map<String, Object> templateParams = new HashMap<>();
                    templateParams.put(VelocityTemplatingConstants.TEMPLATE_NAME, CredentialUtils.getTemplateName(vcRequestDto));
                    templateParams.put(VelocityTemplatingConstants.ISSUER_URI, issuerURI);
                    if (svg != null) {
                        templateParams.put(VelocityTemplatingConstants.SVG_TEMPLATE, svg);
                    }
                    String templatedVC = vcFormatter.format(jsonObject, templateParams);
                    Map<String, String> vcSignerParams = new HashMap<>();
                    // TODO: Collate this into simpler APIs where just key-type is specified
                    if (VCSignAlgo.equals(SignatureAlg.RSA_SIGNATURE_SUITE)) {
                        vcSignerParams.put(KeyManagerConstants.VC_SIGN_ALGO,
                                SignatureAlg.RSA_SIGNATURE_SUITE);
                        vcSignerParams.put(KeyManagerConstants.PUBLIC_KEY_URL, hostedKey);
                        vcSignerParams.put(KeyManagerConstants.KEY_APP_ID, KeyManagerConstants.CERTIFY_MOCK_RSA);
                        vcSignerParams.put(KeyManagerConstants.KEY_REF_ID, KeyManagerConstants.EMPTY_REF_ID);
                        // Change it to PS256 as per --> https://w3c.github.io/vc-jws-2020/#dfn-jsonwebsignature2020
                        vcSignerParams.put(KeyManagerConstants.KEYMGR_SIGN_ALGO, JWSAlgorithm.RS256.getName());
                    } else if (VCSignAlgo.equals(SignatureAlg.ED25519_SIGNATURE_SUITE)) {
                        // https://w3c-ccg.github.io/lds-ed25519-2018/
                        vcSignerParams.put(KeyManagerConstants.VC_SIGN_ALGO, SignatureAlg.ED25519_SIGNATURE_SUITE);
                        vcSignerParams.put(KeyManagerConstants.PUBLIC_KEY_URL, hostedKey);
                        vcSignerParams.put(KeyManagerConstants.KEY_REF_ID, KeyManagerConstants.ED25519_REF_ID);
                        vcSignerParams.put(KeyManagerConstants.KEY_APP_ID, KeyManagerConstants.CERTIFY_MOCK_ED25519);
                        vcSignerParams.put(KeyManagerConstants.KEYMGR_SIGN_ALGO, JWSAlgorithm.EdDSA.getName());
                    }
                    vcResult = vcSigner.perform(templatedVC, vcSignerParams);
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
