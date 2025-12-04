package io.mosip.certify.vcformatters;

import java.util.List;
import java.util.Map;

import io.mosip.certify.api.spi.DataProviderPlugin;
import org.json.JSONArray;

/**
 * VCDataModelFormatter is a templating engine which takes @param templateInput and returns a templated VC.
 * Some implementations include
 * - VC 1.0 & 2.0 data model templating engine using Velocity
 */
public interface VCFormatter {
    /**
     * returns a templated VC as per the data in valueMap & some templateSettings
     *
     * @param finalTemplate data provided by a {@link DataProviderPlugin} implementation.
     * @return a templated & unsigned VC
     */
    String format(Map<String, Object> finalTemplate);
    /**
     * returns the proof algorithm associated with the template name. As defined in rfc7518
     *
     * @param finalTemplate
     * @return
     */
    JSONArray formatQRData(Map<String, Object> finalTemplate);
    String getProofAlgorithm(String templateName);
    /**
     * returns the DID for the given template
     * @param templateName
     * @return
     */
    String getDidUrl(String templateName);
    /**
     * returns the refid. In certain cases it could be empty.
     * @param templateName
     * @return
     */
    String getRefID(String templateName);
    /**
     * returns the app id of the keys as configured during issuer setup.
     * @param templateName
     * @return
     */
    String getAppID(String templateName);

    /**
     * returns the selective disclosure fields for the given template. 
     * @param templateName
     * @return
     */
    List<String> getSelectiveDisclosureInfo(String templateName);

    /**
     * returns the crypto suite used for VC signature or proof generation
     * @param templateName
     * @return
     */
    String getSignatureCryptoSuite(String templateName);

    /**
     * returns the credential status purpose used for adding credentialStatus to the VC.
     * @param templateName
     * @return
     */
    List<String> getCredentialStatusPurpose(String templateName);

    /**
     * returns the QR settings for the given template.
     * @param templateName
     * @return
     */
    List<Map<String, Object>> getQRSettings(String templateName);

    /**
     * returns the QR signature algorithm for the given template.
     * @param templateName
     * @return
     */
    String getQRSignatureAlgo(String templateName);
}