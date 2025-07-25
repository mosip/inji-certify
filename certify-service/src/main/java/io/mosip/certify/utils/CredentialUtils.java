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
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.proofgenerators.ProofGenerator;
import lombok.extern.slf4j.Slf4j;

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
            log.error("Error during canonicalization", e.getMessage());
            throw new CertifyException("Error during canonicalization");
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
            log.error("Error during cryptosuite initialization", e.getMessage());
            throw new CertifyException("Error during cryptosuite initialization");
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
            log.error("Error during canonicalization", e.getMessage());
            throw new CertifyException("Error during canonicalization");
        }

        try {
            signer.sign(ldProofBuilder, canonicalizationResult);
        } catch (GeneralSecurityException e) {
            log.error("Error during signing the VC", e.getMessage());
            throw new CertifyException("Error during signing the VC");
        }

        dataIntegrityProof = ldProofBuilder.build();
        return dataIntegrityProof;
    }
}
