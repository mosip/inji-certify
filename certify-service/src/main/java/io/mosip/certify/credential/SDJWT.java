package io.mosip.certify.credential;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDtoV2;
import org.springframework.stereotype.Component;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDObjectBuilder;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.utils.SDJsonUtils;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.service.SignatureService;
import io.mosip.kernel.signature.service.CoseSignatureService;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Component
public class SDJWT extends Credential{

    private final ObjectMapper objectMapper;

    public SDJWT(VCFormatter vcFormatter, SignatureService signatureService,
                 CoseSignatureService coseSignatureService, ObjectMapper objectMapper){
        super(vcFormatter, signatureService, coseSignatureService);
        this.objectMapper = objectMapper;
    }

    /**
     * This method returns true when a format can be handled.
     */
    @Override
    public boolean canHandle(String format){
        return VCFormats.DC_SD_JWT.equals(format);
    }


        /**
         * createCredential method is resposible to convert the given template and
         * templateparams into the requested credential format. This not just a
         * template replacement but should also have all logics necessary to conver
         * this to a proper verifiable credential.Any additional VC level atributes
         * or context or etc should be handled by the inherrited class.
         * upon error it returns an empty JWT.
         * upon success it returns the unsiged sd-jwt with disclosure
         *
         * @param updatedTemplateParams The params map that would be used to replace the
         *                       template
         * @param templateName   The actual template
         */
    @Override
    public String createCredential(Map<String, Object> updatedTemplateParams, String templateName) {
        SDObjectBuilder sdObjectBuilder = new SDObjectBuilder();
        List<Disclosure> disclosures = new ArrayList<>();
        PlainHeader header = new PlainHeader();
        JsonNode node;
        String currentPath = "$";

        String templatedJSON = super.createCredential(updatedTemplateParams, templateName);
        List<String> sdPaths = super.vcFormatter.getSelectiveDisclosureInfo(templateName);   
        try {
            
            node = objectMapper.readTree(templatedJSON);
            List<String> presentSdPaths = new ArrayList<>();
            String template = null;
            for (String path : sdPaths) {
                if (SDJsonUtils.isPathValid(node, path)) {
                    presentSdPaths.add(path);
                    continue;
                }
                // isPathValid is also false for a malformed path. That is a configuration error, and
                // must not reach the fallback below, which would accept it by its field name alone.
                if (!SDJsonUtils.isPathSyntaxValid(path)) {
                    throw new CertifyException(ErrorConstants.SD_CLAIMS_PARSE_ERROR, "SD-Claim path '" + path + "' is not a valid JSON path.");
                }
                // Only data that is not there may be optional. A value of another shape, such as a
                // string where the path expects an array, would otherwise be issued as a plain claim.
                if (!SDJsonUtils.isPathAbsent(node, path)) {
                    throw new CertifyException(ErrorConstants.SD_CLAIMS_PARSE_ERROR, "SD-Claim path '" + path + "' does not match the structure of the issued credential.");
                }
                // The check runs on this holder's credential, so a field the template emits only
                // conditionally (#if) or as an empty array is missing for some holders. That is not a
                // misconfiguration, and the claim simply has nothing to disclose.
                if (template == null) {
                    template = super.vcFormatter.getTemplate(templateName);
                }
                // The whole path has to be declared: a key of the same name under another object does
                // not make this one optional, and would silently drop the configured disclosure.
                if (!SDJsonUtils.isPathInTemplate(template, path)) {
                    throw new CertifyException(ErrorConstants.SD_CLAIMS_PARSE_ERROR, "SD-Claim path '" + path + "' not found in the issued credential.");
                }
                log.warn("SD-Claim path '{}' is not in the issued credential, but the template declares it, so it is left out for this holder.",
                        path);
            }
            SDJsonUtils.constructSDPayload(node, sdObjectBuilder, disclosures, presentSdPaths, currentPath);
            Map<String,Object>  sdClaims = sdObjectBuilder.build();
            JWTClaimsSet claimsSet = JWTClaimsSet.parse(sdClaims);
            PlainJWT jwt = new PlainJWT(header, claimsSet);
            com.authlete.sd.SDJWT sdJwt = new com.authlete.sd.SDJWT(jwt.serialize(), disclosures);
            return sdJwt.toString();
        } catch (JsonProcessingException ex) {
            log.error("JSON processing error", ex);
            throw new CertifyException(ErrorConstants.JSON_PROCESSING_ERROR, "Failed to process JSON during SD-JWT creation.");
        }
        catch (ParseException ex) {
            log.error("Final SDClaims un parseable. Mostly a bug in the code and has to be reported ", ex);
            throw new CertifyException(ErrorConstants.SD_CLAIMS_PARSE_ERROR, "Failed to parse SD-Claims while creating SD-JWT.");
        }
    }

    /**
     * Adds a signature/proof. Based on the actual implementation the input 
     * could be different, its recommended that the input matches the output 
     * of the respective createCredential, for eg: Base64, Sringified JSON etc.
     * <p>In the defaulat abstract implementation we assume 
     * ```Base64.getUrlEncoder().encodeToString(vcToSign)``` </p>
     * @param vcToSign actual vc as returned by the `createCredential` method. 
     * @param headers headers to be added. Can be null.
     * @param signAlgorithm as defined in com.danubetech.keyformats.jose.JWSAlgorithm
     * @param appID app id from the keymanager tables
     * @param refID referemce id from the keymanager tables
     * @param didUrl url where the public key is accesible.
     */
    @Override
    public VCResult<?> addProof(String vcToSign, String headers, String signAlgorithm, String appID, String refID, String didUrl, String signatureCryptoSuite) {
        VCResult<String> vcResult = new VCResult<>();
        String[] jwt = vcToSign.split("~");
        String[] jwtPayload = jwt[0].split("\\.");
        //TODO: Request DTO should add options for header.
        JWSSignatureRequestDtoV2 payload = new JWSSignatureRequestDtoV2();
        payload.setDataToSign(jwtPayload.length > 1?jwtPayload[1]:jwtPayload[0]);
        payload.setApplicationId(appID);
        payload.setReferenceId(refID);
        payload.setAdditionalHeaders(Map.of("typ", VCFormats.DC_SD_JWT));
        //TODO: Wait for keymanager fix here.
        payload.setSignAlgorithm(signAlgorithm);
        payload.setIncludePayload(true);
        payload.setIncludeCertificateChain(true);
        payload.setIncludeCertHash(true);
        payload.setValidateJson(false);
        payload.setB64JWSHeaderParam(true);
        payload.setCertificateUrl("");
        //payload.setSignAlgorithm(signAlgorithm); // RSSignature2018 --> RS256, PS256, ES256

        JWTSignatureResponseDto jwsSignedData = signatureService.jwsSignV2(payload);
        vcResult.setCredential(vcToSign.replaceAll("^[^~]*", jwsSignedData.getJwtSignedData()));
        return vcResult;
    }

}
