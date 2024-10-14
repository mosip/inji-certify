package io.mosip.certify.services;

import io.mosip.certify.api.dto.VCRequestDto;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * VCIPluginSelecter helps decide which PluginType to choose for issuing credential.
 * Provided, the client apps are
 *
 * Future scope:
 * 1. Decide PluginType based on CredentialRequest & Verify based on
 *    @context, credential.type defined in the request & the well-known, scope
 * 2.
 */
@Component
public class VCIPluginSelecterImpl implements VCIPluginSelecter {
    // TODO: This would have to become a HashMap where-in the ContextURL+Credential.Type
    //  need to be configured to map a specific Plugin to a Credential Request

    @Value("#{${mosip.certify.dataprovider.types}}")
    private Set<String> dataProviderPluginCredentialTypes;
    // TODO: Verify the well-known URL with the well-known config as well
    @Override
    public PluginType choosePlugin(VCRequestDto r) {
        // Match the CredentialType with well-known
        boolean isDataProviderPlugin = r.getType().stream().anyMatch(t -> dataProviderPluginCredentialTypes.contains(t));
        if (isDataProviderPlugin) {
            return PluginType.DataProviderPlugin;
        }
        return PluginType.VCIssuancePlugin;
    }
}
