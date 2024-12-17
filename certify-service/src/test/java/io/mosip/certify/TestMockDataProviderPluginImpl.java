package io.mosip.certify;

import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.services.spi.DataProviderPlugin;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.Map;

@ConditionalOnProperty(value = "mosip.certify.integration.vci-plugin", havingValue = "TestVCIPluginImpl")
@Component
@Slf4j
public class TestMockDataProviderPluginImpl implements DataProviderPlugin {
    @Override
    public JSONObject fetchData(Map<String, Object> identityDetails) throws DataProviderExchangeException {
//        return Map.of();
        return new JSONObject();
    }
}
