package io.mosip.certify.vcformatters;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;


import java.util.List;
import java.util.Map;

@Component
@Primary
public class VCFormatterFactory implements VCFormatter {

    private final VCFormatter delegate;

    public VCFormatterFactory(
            @Qualifier("mdocFormatter") VCFormatter mdocFormatter,
            @Qualifier("velocityFormatter") VCFormatter velocityFormatter,
            @Value("${mosip.certify.integration.data-provider-plugin}") String pluginName
    ) {
        if ("MockMDocDataProviderPlugin".equals(pluginName)) {
            this.delegate = mdocFormatter;
        } else if ("MockCSVDataProviderPlugin".equals(pluginName)) {
            this.delegate = velocityFormatter;
        } else {
            throw new IllegalArgumentException("Unsupported data-provider-plugin: " + pluginName);
        }
    }

    @Override
    public String format(JSONObject valueMap, Map<String, Object> templateSettings) {
        return delegate.format(valueMap, templateSettings);
    }

    @Override
    public String format(Map<String, Object> templateInput) {
        return delegate.format(templateInput);
    }

    @Override
    public String getProofAlgorithm(String templateName) {
        return delegate.getProofAlgorithm(templateName);
    }

    @Override
    public String getDidUrl(String templateName) {
        return delegate.getDidUrl(templateName);
    }

    @Override
    public String getRefID(String templateName) {
        return delegate.getRefID(templateName);
    }

    @Override
    public String getAppID(String templateName) {
        return delegate.getAppID(templateName);
    }

    @Override
    public List<String> getSelectiveDisclosureInfo(String templateName) {
        return delegate.getSelectiveDisclosureInfo(templateName);
    }

    @Override
    public String getSignatureCryptoSuite(String templateName) {
        return delegate.getSignatureCryptoSuite(templateName);
    }

    @Override
    public List<String> getCredentialStatusPurpose(String templateName) {
        return delegate.getCredentialStatusPurpose(templateName);
    }

}