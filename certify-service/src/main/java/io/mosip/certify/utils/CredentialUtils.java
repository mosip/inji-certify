package io.mosip.certify.utils;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;

import com.apicatalog.jsonld.lang.Keywords;
import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.signer.LdSigner;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.proofgenerators.ProofGenerator;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONArray;
import org.json.JSONObject;

@Slf4j
public class CredentialUtils {
    // returns true for VC 2.0 VCI requests
    public static boolean isVC2_0Request(VCRequestDto r) {
        return r.getContext().get(0).equals("https://www.w3.org/ns/credentials/v2");
    }

    /**
     * get the template name for a VCRequest for VCFormatter lib
     * @param vcRequestDto
     * @return
     */
    public static String getTemplateName(VCRequestDto vcRequestDto) {
        //TODO: Cache this entire data so we do not construct all the time.

        if(vcRequestDto.getFormat().equals(VCFormats.VC_SD_JWT)) {
            return String.join(Constants.DELIMITER, vcRequestDto.getFormat(), vcRequestDto.getVct());
        }
        if(vcRequestDto.getFormat().equals(VCFormats.MSO_MDOC)) {
            return String.join(Constants.DELIMITER, vcRequestDto.getFormat(), vcRequestDto.getDoctype());
        }
        List<String> c = new ArrayList<>(vcRequestDto.getContext());
        List<String> t = new ArrayList<>(vcRequestDto.getType());
        Collections.sort(c);
        Collections.sort(t);
        String contextKey = String.join(",", c);
        String typeKey = String.join(",", t);
      //  contextKey = StringUtils.hasText(vcRequestDto.getFormat())?contextKey.concat("-"+vcRequestDto.getFormat()):contextKey;
        return String.join(Constants.DELIMITER, typeKey, contextKey,vcRequestDto.getFormat());
    }

    public static LdProof generateLdProof(LdProof vcLdProof, JsonLDObject j,
                                          Map<String, String> keyReferenceDetails,
                                          ProofGenerator proofGenerator) throws CertifyException {
        Canonicalizer canonicalizer = proofGenerator.getCanonicalizer();
        byte[] vcHashBytes;
        try {
            vcHashBytes = canonicalizer.canonicalize(vcLdProof, j);
        } catch (IOException | GeneralSecurityException | JsonLDException e) {
            log.error("Error occurred during canonicalization.", e);
            throw new CertifyException(ErrorConstants.CANONICALIZATION_ERROR, "Error occurred during canonicalization.");
        }
        String vcEncodedHash = Base64.getUrlEncoder().encodeToString(vcHashBytes);
        LdProof ldProofWithJWS = proofGenerator.generateProof(vcLdProof, vcEncodedHash, keyReferenceDetails);
        return ldProofWithJWS;
    }

    public static DataIntegrityProof generateDataIntegrityProof(DataIntegrityProof dataIntegrityProof, JsonLDObject jsonLDObject, LdSigner signer) {
        DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder = DataIntegrityProof.builder()
                .base(dataIntegrityProof)
                .defaultContexts(false);

        try {
            signer.initialize(ldProofBuilder);
        } catch (GeneralSecurityException e) {
            log.error("Error during cryptosuite initialization", e);
            throw new CertifyException(ErrorConstants.CRYPTOSUITE_INITIALIZATION_ERROR, "Error occurred during crypto suite initialization.");
        }

        DataIntegrityProof ldProofOptions = DataIntegrityProof.fromJson(dataIntegrityProof.toJson());
        if (ldProofOptions.getContexts() == null || ldProofOptions.getContexts().isEmpty()) {
            JsonLDUtils.jsonLdAdd(ldProofOptions, Keywords.CONTEXT, jsonLDObject.getContexts().stream().map(JsonLDUtils::uriToString).filter(Objects::nonNull).toList());
        }

        com.danubetech.dataintegrity.canonicalizer.Canonicalizer canonicalizer = signer.getCanonicalizer(ldProofOptions);

        byte[] canonicalizationResult;
        try {
            canonicalizationResult = canonicalizer.canonicalize(ldProofOptions, jsonLDObject);
        } catch (IOException | GeneralSecurityException | JsonLDException e) {
            log.error("Error occurred during canonicalization.", e);
            throw new CertifyException(ErrorConstants.CANONICALIZATION_ERROR, "Error occurred during canonicalization.");
        }

        try {
            signer.sign(ldProofBuilder, canonicalizationResult);
        } catch (GeneralSecurityException e) {
            log.error("Error occurred while signing the Verifiable Credential.", e);
            throw new CertifyException(ErrorConstants.VC_SIGNING_ERROR, "Error occurred while signing the Verifiable Credential.");
        }

        dataIntegrityProof = ldProofBuilder.build();
        return dataIntegrityProof;
    }

    /**
     * jsonify wraps a complex object into it's JSON representation
     * @param valueMap
     * @return
     */
    public static Map<String, Object> toJsonMap(Map<String, Object> valueMap) {
        Map<String, Object> finalTemplate = new HashMap<>();
        Iterator<String> keys = valueMap.keySet().iterator();
        while(keys.hasNext()) {
            String key = keys.next();
            Object value = valueMap.get(key);
            if(key == null || value == null) {
                continue;
            }
            if (value instanceof List) {
                finalTemplate.put(key, new JSONArray((List<Object>) value));
            } else if (value.getClass().isArray()) {
                finalTemplate.put(key, new JSONArray(List.of(value)));
            } else if (value instanceof Integer | value instanceof Float | value instanceof Long | value instanceof Double) {
                // entities which don't need to be quoted
                finalTemplate.put(key, value);
            } else if (value instanceof String){
                // entities which need to be quoted
                finalTemplate.put(key, JSONObject.wrap(value));
            } else if( value instanceof Map<?,?>) {
                finalTemplate.put(key,JSONObject.wrap(value));
            }
            else {
                // no conversion needed
                finalTemplate.put(key, value);
            }
        }
        return finalTemplate;
    }
}
