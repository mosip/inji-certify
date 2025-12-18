package io.mosip.certify.services;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.AuthorizationServerConfig;
import io.mosip.certify.core.dto.AuthorizationServerMetadata;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import io.mosip.certify.services.VCICacheService;

import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for discovering and caching authorization server metadata
 */
@Service
@Slf4j
public class AuthorizationServerService {

    @Autowired
    private VCICacheService vciCacheService;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RestTemplate restTemplate;

    @Value("${mosip.certify.authorization.discovery.retry-count:3}")
    private int retryCount;

    @Value("${mosip.certify.authorization.servers:}")
    private String authorizationServersConfig;

    @Value("${mosip.certify.authorization.internal.url:}")
    private String internalAuthServerUrl;

    @Value("${mosip.certify.authorization.default-server:}")
    private String defaultAuthServer;

    @Value("${mosip.certify.credential-config.as-mapping:{}}")
    private String credentialConfigMappingJson;

    private List<AuthorizationServerConfig> configuredServers;
    private Map<String, String> credentialConfigToASMapping;

    @PostConstruct
    public void initialize() {
        log.info("Initializing Authorization Server Management Service");

        configuredServers = new ArrayList<>();
        loadConfiguredServers();
        loadCredentialConfigMappings();

        log.info("Configured {} authorization servers", configuredServers.size());
        log.info("Loaded {} credential configuration mappings", credentialConfigToASMapping.size());
    }

    private void loadConfiguredServers() {
        // Add internal auth server
        if (StringUtils.hasText(internalAuthServerUrl)) {
            AuthorizationServerConfig internal = AuthorizationServerConfig.builder()
                    .serverId("internal")
                    .serverUrl(internalAuthServerUrl)
                    .internal(true)
                    .build();
            configuredServers.add(internal);
            log.info("Added internal authorization server: {}", internalAuthServerUrl);
        }

        // Parse external auth servers
        if (StringUtils.hasText(authorizationServersConfig)) {
            String[] servers = authorizationServersConfig.split(",");
            for (String serverUrl : servers) {
                serverUrl = serverUrl.trim();
                if (StringUtils.hasText(serverUrl)) {
                    AuthorizationServerConfig config = AuthorizationServerConfig.builder()
                            .serverId(generateServerId(serverUrl))
                            .serverUrl(serverUrl)
                            .internal(false)
                            .build();
                    configuredServers.add(config);
                    log.info("Added external authorization server: {}", serverUrl);
                }
            }
        }

        if (configuredServers.isEmpty()) {
            log.warn("No authorization servers configured");
        }
    }

    private void loadCredentialConfigMappings() {
        credentialConfigToASMapping = new HashMap<>();

        try {
            if (StringUtils.hasText(credentialConfigMappingJson) &&
                    !credentialConfigMappingJson.trim().equals("{}")) {

                Map<String, String> mappings = objectMapper.readValue(
                        credentialConfigMappingJson,
                        new TypeReference<Map<String, String>>() {
                        });

                credentialConfigToASMapping.putAll(mappings);
                log.info("Loaded credential config mappings: {}", mappings);
            }
        } catch (Exception e) {
            log.error("Failed to parse credential config mappings", e);
        }
    }

    /**
     * Get internal authorization server metadata
     */
    public AuthorizationServerMetadata getInternalAuthServerMetadata() {
        // For internal server, we can construct metadata directly
        AuthorizationServerMetadata metadata = new AuthorizationServerMetadata();
        metadata.setIssuer(normalizeUrl(internalAuthServerUrl));
        metadata.setTokenEndpoint(normalizeUrl(internalAuthServerUrl) + "/token");
        metadata.setAuthorizationEndpoint(normalizeUrl(internalAuthServerUrl) + "/authorize");
        metadata.setJwksUri(normalizeUrl(internalAuthServerUrl) + "/jwks.json");

        return metadata;
    }

    /**
     * Discover authorization server metadata from well-known endpoint
     */
    public AuthorizationServerMetadata discoverMetadata(String serverUrl) {
        log.info("Discovering authorization server metadata for: {}", serverUrl);

        // Check cache first
        AuthorizationServerMetadata cached = vciCacheService.getASMetadata(serverUrl);
        if (cached != null) {
            log.info("Using cached AS metadata for: {}", serverUrl);
            return cached;
        }

        // Try OIDC config first (per RFC 8414 compatibility notes), then OAuth AS
        // discovery
        AuthorizationServerMetadata metadata = tryDiscoveryEndpoint(serverUrl, Constants.WELL_KNOWN_OIDC_CONFIG);
        if (metadata == null) {
            log.info("OIDC configuration discovery failed, trying OAuth AS endpoint");
            metadata = tryDiscoveryEndpoint(serverUrl, Constants.WELL_KNOWN_OAUTH_AS);
        }

        if (metadata == null) {
            log.error("Failed to discover AS metadata for: {}", serverUrl);
            throw new CertifyException(ErrorConstants.AUTHORIZATION_SERVER_DISCOVERY_FAILED,
                    "Could not discover authorization server metadata");
        }

        // Cache the metadata
        vciCacheService.setASMetadata(serverUrl, metadata);
        log.info("Successfully discovered and cached AS metadata for: {}", serverUrl);

        return metadata;
    }

    private AuthorizationServerMetadata tryDiscoveryEndpoint(String serverUrl, String wellKnownPath) {
        String discoveryUrl = normalizeUrl(serverUrl) + wellKnownPath;

        for (int attempt = 1; attempt <= retryCount; attempt++) {
            try {
                log.debug("Discovery attempt {} for URL: {}", attempt, discoveryUrl);

                ResponseEntity<String> response = restTemplate.getForEntity(new URI(discoveryUrl), String.class);

                if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                    AuthorizationServerMetadata metadata = objectMapper.readValue(
                            response.getBody(),
                            AuthorizationServerMetadata.class);

                    validateMetadata(metadata, serverUrl);
                    return metadata;
                }
            } catch (Exception e) {
                log.warn("Discovery attempt {} failed for {}: {}", attempt, discoveryUrl, e.getMessage());
                if (attempt == retryCount) {
                    log.error("All discovery attempts failed for: {}", discoveryUrl, e);
                }
            }
        }
        return null;
    }

    private void validateMetadata(AuthorizationServerMetadata metadata, String expectedIssuer) {
        if (metadata == null
                || !StringUtils.hasText(metadata.getIssuer())
                || !StringUtils.hasText(metadata.getTokenEndpoint())) {
            throw new CertifyException(ErrorConstants.AUTHORIZATION_SERVER_DISCOVERY_FAILED);
        }

        // Validate issuer matches expected URL
        String normalizedExpected = normalizeUrl(expectedIssuer);
        String normalizedActual = normalizeUrl(metadata.getIssuer());

        if (!normalizedActual.equals(normalizedExpected)) {
            log.warn("Issuer mismatch: expected {}, got {}", normalizedExpected, normalizedActual);
        }
    }

    /**
     * Get token endpoint for a specific authorization server
     */
    public String getTokenEndpoint(String serverUrl) {
        AuthorizationServerMetadata metadata = discoverMetadata(serverUrl);
        return metadata.getTokenEndpoint();
    }

    /**
     * Get JWKS URI for a specific authorization server
     */
    public String getJwksUri(String serverUrl) {
        AuthorizationServerMetadata metadata = discoverMetadata(serverUrl);
        return metadata.getJwksUri();
    }

    /**
     * Check if authorization server supports pre-authorized code grant
     */
    public boolean supportsPreAuthorizedCodeGrant(String serverUrl) {
        try {
            AuthorizationServerMetadata metadata = discoverMetadata(serverUrl);
            List<String> grantTypes = metadata.getGrantTypesSupported();
            return grantTypes != null && grantTypes.contains(Constants.PRE_AUTHORIZED_CODE_GRANT_TYPE);
        } catch (Exception e) {
            log.warn("Could not check grant type support for {}: {}", serverUrl, e.getMessage());
            return false;
        }
    }

    /**
     * Get authorization server for a specific credential configuration
     */
    public String getAuthorizationServerForCredentialConfig(String credentialConfigId) {
        log.debug("Getting authorization server for credential config: {}", credentialConfigId);

        // Check if there's a specific mapping
        String mappedServerUrl = credentialConfigToASMapping.get(credentialConfigId);
        if (StringUtils.hasText(mappedServerUrl)) {
            validateServerConfigured(mappedServerUrl);
            log.debug("Found mapped AS for {}: {}", credentialConfigId, mappedServerUrl);
            return mappedServerUrl;
        }

        // Use default server if configured
        if (StringUtils.hasText(defaultAuthServer)) {
            validateServerConfigured(defaultAuthServer);
            log.debug("Using default AS for {}: {}", credentialConfigId, defaultAuthServer);
            return defaultAuthServer;
        }

        // Fall back to internal server
        if (StringUtils.hasText(internalAuthServerUrl)) {
            log.debug("Using internal AS for {}: {}", credentialConfigId, internalAuthServerUrl);
            return internalAuthServerUrl;
        }

        log.error("No authorization server found for credential config: {}", credentialConfigId);
        throw new CertifyException(ErrorConstants.AUTHORIZATION_SERVER_NOT_CONFIGURED,
                "No authorization server configured for credential configuration: " + credentialConfigId);
    }

    /**
     * Get all configured authorization server URLs
     */
    public List<String> getAllAuthorizationServerUrls() {
        return configuredServers.stream()
                .map(AuthorizationServerConfig::getServerUrl)
                .collect(Collectors.toList());
    }

    /**
     * Check if a server URL is configured
     */
    public boolean isServerConfigured(String serverUrl) {
        String normalized = normalizeUrl(serverUrl);
        return configuredServers.stream()
                .anyMatch(config -> normalizeUrl(config.getServerUrl()).equals(normalized));
    }

    private void validateServerConfigured(String serverUrl) {
        if (!isServerConfigured(serverUrl)) {
            log.error("Authorization server not configured: {}", serverUrl);
            throw new InvalidRequestException(ErrorConstants.INVALID_AUTHORIZATION_SERVER);
        }
    }

    /**
     * Normalize URL by removing trailing slashes
     */
    private String normalizeUrl(String url) {
        if (url == null) {
            return "";
        }
        return url.replaceAll("/+$", "");
    }

    /**
     * Generate unique server ID from URL
     */
    private String generateServerId(String serverUrl) {
        try {
            String normalized = normalizeUrl(serverUrl);
            String domain = normalized.replaceAll("https?://", "")
                    .replaceAll("[^a-zA-Z0-9-]", "-");
            return "as-" + domain;
        } catch (Exception e) {
            return "as-" + UUID.randomUUID().toString();
        }
    }
}