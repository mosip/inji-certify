package io.mosip.certify.services;

import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.StatusListAvailableIndices;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.StatusListAvailableIndicesRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import java.math.BigInteger;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
public class DatabaseStatusListIndexProvider implements StatusListIndexProvider {

    @Autowired
    private StatusListAvailableIndicesRepository statusListAvailableIndicesRepository;

    @Autowired
    private StatusListCredentialRepository statusListCredentialRepository;

    @Autowired
    private EntityManager entityManager;

    @Value("${mosip.certify.statuslist.usable-capacity-percentage:50}")
    private int usableCapacityPercentage;

    @Override
    public String getProviderName() {
        return "DatabaseRandomAvailableIndexProvider";
    }

    @Override
    @Transactional
    public Optional<Long> acquireIndex(String listId, Map<String, Object> options) {
        log.debug("Attempting to acquire index for status list: {}", listId);

        try {
            // 1. Get status list and its capacity
            Optional<StatusListCredential> statusListOpt = statusListCredentialRepository.findById(listId);
            if (statusListOpt.isEmpty()) {
                log.error("Status list not found: {}", listId);
                return Optional.empty();
            }

            StatusListCredential statusList = statusListOpt.get();
            long physicalCapacity = statusList.getCapacity();

            // 2. Calculate effective threshold based on usable capacity
            long effectiveThresholdCount = (long) Math.floor(physicalCapacity * (usableCapacityPercentage / 100.0));

            // 3. Check current assigned count
            long currentAssignedCount = statusListAvailableIndicesRepository
                    .countByStatusListCredentialIdAndIsAssignedTrue(listId);

            if (currentAssignedCount >= effectiveThresholdCount) {
                log.warn("Status list {} has reached usable capacity limit ({}/{})",
                        listId, currentAssignedCount, effectiveThresholdCount);

                // Mark status list as full
                statusList.setCredentialStatus(StatusListCredential.CredentialStatus.FULL);
                statusListCredentialRepository.save(statusList);

                return Optional.empty();
            }

            // 4. Attempt to atomically claim an index using native query
            Long claimedIndex = atomicallyClaimIndex(listId);

            if (claimedIndex != null) {
                log.info("Successfully claimed index {} for status list: {}", claimedIndex, listId);
                return Optional.of(claimedIndex);
            } else {
                log.warn("Failed to claim any available index for status list: {}", listId);
                return Optional.empty();
            }

        } catch (Exception e) {
            log.error("Error acquiring index for status list: {}", listId, e);
            return Optional.empty();
        }
    }

    /**
     * Atomically claim an available index using database skip lock mechanism
     */
    private Long atomicallyClaimIndex(String listId) {
        try {
            String sql = """
                WITH available_slot AS (
                    SELECT list_index
                    FROM status_list_available_indices
                    WHERE status_list_credential_id = :listId 
                        AND is_assigned = false
                    ORDER BY RANDOM()
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
                UPDATE status_list_available_indices sla
                SET is_assigned = true,
                    upd_dtimes = NOW()
                FROM available_slot avs
                WHERE sla.status_list_credential_id = :listId
                    AND sla.list_index = avs.list_index
                    AND sla.is_assigned = false
                RETURNING sla.list_index
                """;

            Query query = entityManager.createNativeQuery(sql);
            query.setParameter("listId", listId);

            Object result = query.getSingleResult();

            if (result != null) {
                if (result instanceof BigInteger) {
                    return ((BigInteger) result).longValue();
                } else if (result instanceof Long) {
                    return (Long) result;
                } else if (result instanceof Integer) {
                    return ((Integer) result).longValue();
                }
            }

            return null;

        } catch (Exception e) {
            log.debug("No available index found or error in atomic claim for list: {}", listId);
            return null;
        }
    }
}