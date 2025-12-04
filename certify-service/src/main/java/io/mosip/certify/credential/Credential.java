/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package io.mosip.certify.credential;

import java.util.Map;

import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.service.SignatureService;
import org.json.JSONArray;


public abstract class Credential{
    
    protected VCFormatter vcFormatter;

    protected SignatureService signatureService;

    /**
     * Constructor for credentials
     * @param vcFormatter
     * @param signatureService
     */
    public Credential(VCFormatter vcFormatter, SignatureService signatureService){
        this.vcFormatter = vcFormatter;
        this.signatureService = signatureService;
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
     * @param finalTemplate The params map that would be used to replace the
     *                       template
     * @param templateName   The actual template
     */
    public String createCredential(Map<String, Object> finalTemplate, String templateName) {
        
        finalTemplate.put(Constants.TEMPLATE_NAME, templateName);
        return vcFormatter.format(finalTemplate);
    }

    /**
     * Creates the QR data(JSON Array) based on the final template and template name
     * @param finalTemplate The params map that would be used to replace the
     *                       template
     * @param templateName   The actual template
     * @return JSON Array representing the QR data
     */
    public JSONArray createQRData(Map<String, Object> finalTemplate, String templateName) {
        finalTemplate.put(Constants.TEMPLATE_NAME, templateName);
        return vcFormatter.formatQRData(finalTemplate);
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

}
