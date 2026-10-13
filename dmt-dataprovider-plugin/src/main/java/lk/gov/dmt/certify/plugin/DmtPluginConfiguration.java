package lk.gov.dmt.certify.plugin;

import lk.gov.dmt.certify.plugin.application.ProviderRequestFactory;
import lk.gov.dmt.certify.plugin.application.VcDataFetcherRegistry;
import lk.gov.dmt.certify.plugin.config.DmtProviderProperties;
import lk.gov.dmt.certify.plugin.credential.erl.ErlDataFetcher;
import lk.gov.dmt.certify.plugin.spi.DmtDataClient;
import lk.gov.dmt.certify.plugin.spi.VcDataFetcher;
import lk.gov.dmt.certify.plugin.transport.DmtApiClient;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import java.util.List;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "mosip.certify.integration", name = "data-provider-plugin", havingValue = "MasterDataProviderPlugin")
@EnableConfigurationProperties(DmtProviderProperties.class)
public class DmtPluginConfiguration {
    @Bean(destroyMethod = "close")
    DmtApiClient dmtApiClient(DmtProviderProperties properties) {
        return new DmtApiClient(properties);
    }

    @Bean
    ErlDataFetcher erlDataFetcher(DmtDataClient client) {
        return new ErlDataFetcher(client);
    }

    @Bean
    ProviderRequestFactory providerRequestFactory() { return new ProviderRequestFactory(); }

    @Bean
    VcDataFetcherRegistry vcDataFetcherRegistry(DmtProviderProperties properties, List<VcDataFetcher> fetchers) {
        return new VcDataFetcherRegistry(properties, fetchers);
    }

    @Bean
    MasterDataProviderPlugin masterDataProviderPlugin(VcDataFetcherRegistry registry,
                                                       ProviderRequestFactory requestFactory) {
        return new MasterDataProviderPlugin(registry, requestFactory);
    }
}
