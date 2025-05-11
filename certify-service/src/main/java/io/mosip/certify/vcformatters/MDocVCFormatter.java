package io.mosip.certify.vcformatters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import io.mosip.certify.config.ISO18013Config;
import io.mosip.certify.model.MobileSecurityObject;
import org.json.JSONObject;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.util.*;

@Component
public class MDocVCFormatter implements VCFormatter {
    @Override
    public String format(JSONObject valueMap, Map<String, Object> templateSettings) {
        try {
            // Map only 3 fields
            Map<String, Object> mapped = new HashMap<>();
            if (valueMap.has("family_name")) mapped.put(ISO18013Config.FAMILY_NAME, valueMap.get("family_name"));
            if (valueMap.has("given_name")) mapped.put(ISO18013Config.GIVEN_NAME, valueMap.get("given_name"));
            if (valueMap.has("birth_date")) mapped.put(ISO18013Config.BIRTH_DATE, valueMap.get("birth_date"));

            // Calculate digests
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            ObjectMapper cbor = new ObjectMapper(new CBORFactory());
            Map<String, byte[]> digests = new HashMap<>();
            for (Map.Entry<String, Object> e : mapped.entrySet()) {
                byte[] bytes = cbor.writeValueAsBytes(e.getValue());
                digests.put(e.getKey(), md.digest(bytes));
            }

            // Build MSO
            MobileSecurityObject mso = new MobileSecurityObject();
            mso.setVersion("1.0");
            mso.setDigestAlgorithm("SHA-256");
            mso.setValueDigests(digests);
            mso.setDocType("org.iso.18013.5.1.mDL");

            // Prepare credentialSubject
            Map<String, Object> credSubj = new HashMap<>();
            credSubj.put("docType", "org.iso.18013.5.1.mDL");
            credSubj.put("nameSpaces", Collections.singletonMap(ISO18013Config.MDL_NAMESPACE, mapped));
            credSubj.put("mso", mso);

            // CBOR encode
            byte[] cborCred = cbor.writeValueAsBytes(credSubj);

            // Build VC
            Map<String, Object> vc = new HashMap<>();
            vc.put("@context", Arrays.asList("https://www.w3.org/2018/credentials/v1"));
            vc.put("type", Arrays.asList("VerifiableCredential", "Iso180135_1_mDL"));
            vc.put("issuer", templateSettings.getOrDefault("issuer", "did:example:issuer"));
            vc.put("issuanceDate", new Date().toInstant().toString());
            vc.put("credentialSubject", Base64.getUrlEncoder().encodeToString(cborCred));
            return new ObjectMapper().writeValueAsString(vc);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
} 