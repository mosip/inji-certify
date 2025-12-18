package io.mosip.certify.core.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * Configuration for a single authorization server
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthorizationServerConfig implements Serializable {
    private static final long serialVersionUID = 1L;

    private String serverId;
    private String serverUrl;
    private boolean internal;
    private String wellKnownUrl;
    private long metadataCachedAt;
    private AuthorizationServerMetadata metadata;
}