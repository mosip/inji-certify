package io.mosip.certify.vcformatters;

import java.util.List;
import java.util.Map;

import org.json.JSONObject;

import io.mosip.certify.api.spi.DataProviderPlugin;
/**
 * VCDataModelFormatter is a templating engine which takes @param templateInput and returns a templated VC.
 * Some implementations include
 * - VC 1.0 & 2.0 data model templating engine using Velocity
 */
public interface VCFormatter {
    /**
     * returns a templated VC as per the data in valueMap & some templateSettings
     * @param valueMap data provided by a {@link DataProviderPlugin} implementation.
     * @param templateSettings configurable tunables
     * @return a templated & unsigned VC
     */
    String format(JSONObject valueMap, Map<String, Object> templateSettings);
    /**
     * returns a templated VC as per the data in valueMap & some templateSettings
     * @param templateInput data provided by a {@link DataProviderPlugin} implementation.
     * @return a templated & unsigned VC
     */
    String format(Map<String, Object> templateInput);
    /**
     * returns the proof algorithm associated with the template name. As defined in rfc7518
     * @param templateName
     * @return
     */
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
}