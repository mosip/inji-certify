package lk.gov.dmt.certify.plugin.config;

import jakarta.validation.Valid;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;

@ConfigurationProperties("dmt.data-provider")
@Validated
public record DmtProviderProperties(boolean enabled, @Valid Map<String, Client> clients,
                                    @Valid Map<String, Route> vcTypes) {
    public DmtProviderProperties {
        clients = clients == null ? Map.of() : Map.copyOf(clients);
        vcTypes = vcTypes == null ? Map.of() : Map.copyOf(vcTypes);
    }

    public record Client(URI baseUrl, Duration connectTimeout, Duration exchangeTimeout,
                         int maxResponseBytes, String trustedIssuer, @Valid Authentication authentication) {}

    public record Authentication(String apiKeyHeader, String apiKey) {
        @Override
        public String toString() {
            return "Authentication[credentials=<redacted>]";
        }
    }

    public record Route(boolean enabled, String strategyId, List<String> authorizedScopes,
                        String clientId, String endpointPath) {
        public Route {
            authorizedScopes = authorizedScopes == null ? List.of() : List.copyOf(authorizedScopes);
        }
    }
}
