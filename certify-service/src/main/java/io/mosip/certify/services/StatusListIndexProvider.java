package io.mosip.certify.services;

import java.util.Map;
import java.util.Optional;

/**
 * Interface for providing status list index assignment strategies
 */
public interface StatusListIndexProvider {

    /**
     * @return A descriptive name or identifier for this index provider strategy
     * (e.g., "DatabaseRandomAvailableIndexProvider", "RedisSequentialIndexProvider").
     */
    String getProviderName();

    /**
     * Attempts to acquire an available index from the specified status list.
     * <p>
     * The implementing class is responsible for ensuring the returned index is unique
     * for the given listId at the time of acquisition and that it respects
     * the list's capacity and any applicable usage policies (like usableCapacity).
     *
     * @param listId  The unique identifier of the status list from which to acquire an index.
     * @param options A map of optional parameters that might influence the index acquisition.
     *                This allows for flexibility in implementations. Examples:
     *                - "preferredIndex": (Long) a hint for a desired index, if supported.
     *                - "purpose": (String) context for why the index is needed, could influence choice.
     */
    Optional<Long> acquireIndex(String listId, Map<String, Object> options);

}