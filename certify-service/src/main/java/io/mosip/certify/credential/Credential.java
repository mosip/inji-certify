package io.mosip.certify.credential;

import java.util.HashMap;
import java.util.Map;

import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.dto.CWTSignRequestDto;
import io.mosip.kernel.signature.dto.CoseSignResponseDto;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.service.CoseSignatureService;
import io.mosip.kernel.signature.service.SignatureService;
import io.mosip.kernel.signature.service.impl.CoseSignatureServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONArray;


@Slf4j
public abstract class Credential{
    
    protected VCFormatter vcFormatter;

    protected SignatureService signatureService;

    private final CoseSignatureService coseSignatureService;

    /**
     * Constructor for credentials
     * @param vcFormatter
     * @param signatureService
     * @param coseSignatureService
     */
    protected Credential(VCFormatter vcFormatter, SignatureService signatureService,
                         CoseSignatureService coseSignatureService){
        this.vcFormatter = vcFormatter;
        this.signatureService = signatureService;
        this.coseSignatureService = coseSignatureService;
    }

    /**
     * lets the factory know if the instance can handle the given format or not.
     * @param format
     * @return
     */
    public abstract boolean canHandle(String format);


    /**
     * createCredential method is resposible to convert the given template and
     * templateparams into the requested credential format. This not just a
     * template replacement but should also have all logics necessary to conver
     * this to a proper verifiable credential.Any additional VC level atributes
     * or context or etc should be handled by the inherrited class.
     *
     * @param updatedTemplateParams The params map that would be used to replace the
     *                       template
     * @param templateName   The actual template
     */
    public String createCredential(Map<String, Object> updatedTemplateParams, String templateName) {

        updatedTemplateParams.put(Constants.TEMPLATE_NAME, templateName);
        return vcFormatter.format(updatedTemplateParams);
    }

    /**
     * Creates the QR data(JSON Array) based on the final template and template name
     * @param updatedTemplateParams The params map that would be used to replace the
     *                       template
     * @param templateName   The actual template
     * @return JSON Array representing the QR data
     */
    public JSONArray createQRData(Map<String, Object> updatedTemplateParams, String templateName) {
        updatedTemplateParams.put(Constants.TEMPLATE_NAME, templateName);
        return vcFormatter.formatQRData(updatedTemplateParams);
    }

    /**
     * Creates a signature/proof and based on the actual implementation the input 
     * could be different, for eg: Base64, Sringified JSON etc.
     * <p>In the defaulat abstract implementation we assume 
     * ```Base64.getUrlEncoder().encodeToString(vcInBytes)``` </p>
     * @param vcToSign actual vc bytes 
     * @param headers headers to be added. Can be null.
     * @param signAlgorithm Signature algorithm RS256, PS256, ES256, etc
     * @param appID application id as per the keymanager table
     * @param refID reference id as per the keyamanger table
     * @param didUrl URL/URI of the public key
     */
    public VCResult<?> addProof(String vcToSign, String headers, String signAlgorithm, String appID, String refID, String didUrl, String signatureCryptoSuite) {

        JWSSignatureRequestDto payload = new JWSSignatureRequestDto();
        payload.setDataToSign(vcToSign);
        payload.setApplicationId(appID);
        payload.setReferenceId(refID); 
        payload.setIncludePayload(false);
        payload.setIncludeCertificate(false);
        payload.setIncludeCertHash(true);
        payload.setValidateJson(false);
        payload.setB64JWSHeaderParam(false);
        payload.setCertificateUrl(didUrl);
        payload.setSignAlgorithm(signAlgorithm); // RSSignature2018 --> RS256, PS256, ES256
        JWTSignatureResponseDto jwsSignedData = signatureService.jwsSign(payload);
        VCResult<String> vc = new VCResult<>();
        //TODO: Get the correct default
        vc.setFormat("vc");
        vc.setCredential(jwsSignedData.getJwtSignedData());
        return vc;
    }

    /*
    * Signs the QR data payload using CWT signature
    * @param payload The QR data payload to be signed
    * @param qrSignAlgorithm The QR signing algorithm
    * @param appID Application ID for key retrieval
    * @param refID Reference ID for key retrieval
    * @param didUrl DID URL of the issuer
    */
    public String signQRData(String payload, String qrSignAlgorithm, String appID, String refID, String didUrl) {
        CWTSignRequestDto cwtSignRequestDto = new CWTSignRequestDto();
        cwtSignRequestDto.setClaim169Payload(payload);
        cwtSignRequestDto.setApplicationId(appID);
        cwtSignRequestDto.setReferenceId(refID);
        cwtSignRequestDto.setAlgorithm(qrSignAlgorithm);
        cwtSignRequestDto.setIssuer(didUrl);

        Map<String, Object> protectedHeaders = new HashMap<>();
        protectedHeaders.put("x5c", true);
        protectedHeaders.put("kid", true);

        cwtSignRequestDto.setProtectedHeader(protectedHeaders);
        log.info("CWT sign request DTO built successfully");
        CoseSignResponseDto coseSignResponseDto = coseSignatureService.cwtSign(cwtSignRequestDto);

        return coseSignResponseDto.getSignedData();
    }

}
