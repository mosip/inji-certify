package lk.gov.dmt.certify.plugin.validation;

import lk.gov.dmt.certify.plugin.config.DmtProviderProperties;

import java.net.URI;
import java.time.Duration;
import java.util.HashSet;
import java.util.Set;

import static lk.gov.dmt.certify.plugin.validation.TextValidation.*;

/** Validate configuration without including URLs, identities or secrets in errors. */
public final class DmtConfigurationValidator {
    private DmtConfigurationValidator() {}

    public static void validate(DmtProviderProperties properties) {
        require(properties.enabled(), "DMT provider must be enabled when selected");
        require(!properties.clients().isEmpty(), "At least one API client is required");
        properties.clients().values().forEach(DmtConfigurationValidator::validateClient);
        Set<String> scopes = new HashSet<>();
        long enabled = properties.vcTypes().entrySet().stream().filter(e -> e.getValue().enabled()).count();
        require(enabled > 0, "At least one enabled credential route is required");
        properties.vcTypes().forEach((type, route) -> {
            require(type.matches("[A-Z][A-Z0-9_]*"), "Invalid VC type identifier");
            if (!route.enabled()) return;
            require(text(route.strategyId()) && route.strategyId().matches("[a-z][a-z0-9-]*"), "Invalid strategy identifier");
            require(text(route.clientId()) && properties.clients().containsKey(route.clientId()), "Route references an unknown client");
            require(!route.authorizedScopes().isEmpty(), "Enabled route requires scopes");
            for (String scope : route.authorizedScopes()) {
                require(!scope.isEmpty() && scope.chars().allMatch(c -> c >= 0x21 && c <= 0x7e && c != 34 && c != 92), "Invalid authorized scope");
                require(scopes.add(scope), "Duplicate authorized scope");
            }
            EndpointTemplates.variables(route.endpointPath());
        });
    }

    private static void validateClient(DmtProviderProperties.Client client) {
        URI base = client.baseUrl();
        require(base != null && "https".equalsIgnoreCase(base.getScheme()) && base.getHost() != null
                && base.getRawUserInfo() == null && base.getRawQuery() == null && base.getRawFragment() == null
                && (base.getPort() == -1 || base.getPort() > 0 && base.getPort() <= 65535), "Invalid HTTPS base URL");
        // Paths are deliberately restricted to simple deployment-controlled segments.
        require(base.getRawPath().matches("(?:/[a-zA-Z0-9_-]+)*/?"), "Invalid base URL path");
        validateDuration(client.connectTimeout());
        validateDuration(client.exchangeTimeout());
        require(client.maxResponseBytes() > 0 && client.maxResponseBytes() <= 1048576, "Invalid response size limit");
        require(text(client.trustedIssuer()) && !controls(client.trustedIssuer()), "Trusted identity issuer is required");
        var auth = client.authentication();
        require(auth != null && text(auth.apiKeyHeader()) && auth.apiKeyHeader().matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+"), "Invalid API key header name");
        require(!Set.of("host", "content-length", "connection", "upgrade", "expect", "transfer-encoding")
                .contains(auth.apiKeyHeader().toLowerCase(java.util.Locale.ROOT)), "Reserved API key header name");
        require(text(auth.apiKey()) && auth.apiKey().length() <= 8192
                && auth.apiKey().chars().allMatch(c -> c >= 0x20 && c <= 0x7e), "Invalid API key header value");
    }

    private static void validateDuration(Duration duration) {
        require(duration != null && !duration.isNegative() && !duration.isZero()
                && duration.compareTo(Duration.ofMinutes(1)) <= 0, "Timeout must be positive and at most one minute");
    }

}
