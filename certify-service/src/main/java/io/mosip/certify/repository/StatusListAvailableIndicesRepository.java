package io.mosip.certify.repository;

import io.mosip.certify.entity.StatusListAvailableIndices;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Repository
public interface StatusListAvailableIndicesRepository extends JpaRepository<StatusListAvailableIndices, Long> {

    List<StatusListAvailableIndices> findByStatusListCredentialId(String statusListCredentialId);
    List<StatusListAvailableIndices> findByStatusListCredentialIdAndIsAssignedFalseOrderByListIndexAsc(
            String statusListCredentialId);
    List<StatusListAvailableIndices> findByStatusListCredentialIdAndIsAssignedTrueOrderByListIndexAsc(
            String statusListCredentialId);
    Optional<StatusListAvailableIndices> findByStatusListCredentialIdAndListIndex(
            String statusListCredentialId, Long listIndex);
    Optional<StatusListAvailableIndices> findFirstByStatusListCredentialIdAndIsAssignedFalseOrderByListIndexAsc(
            String statusListCredentialId);
    long countByStatusListCredentialIdAndIsAssignedFalse(String statusListCredentialId);
    long countByStatusListCredentialId(String statusListCredentialId);
    boolean existsByStatusListCredentialIdAndIsAssignedFalse(String statusListCredentialId);

    /**
     * Assign an index (mark as assigned)
     */
    @Modifying
    @Transactional
    @Query("UPDATE StatusListAvailableIndices s SET s.isAssigned = true, s.updatedDtimes = CURRENT_TIMESTAMP " +
            "WHERE s.statusListCredentialId = :credentialId AND s.listIndex = :index")
    int assignIndex(@Param("credentialId") String statusListCredentialId, @Param("index") Long listIndex);

    /**
     * Batch assign multiple indices
     */
    @Modifying
    @Transactional
    @Query("UPDATE StatusListAvailableIndices s SET s.isAssigned = true, s.updatedDtimes = CURRENT_TIMESTAMP " +
            "WHERE s.statusListCredentialId = :credentialId AND s.listIndex IN :indices")
    int assignIndices(@Param("credentialId") String statusListCredentialId, @Param("indices") List<Long> listIndices);

    /**
     * Find available indices within a range
     */
    @Query("SELECT s FROM StatusListAvailableIndices s WHERE s.statusListCredentialId = :credentialId " +
            "AND s.isAssigned = false AND s.listIndex BETWEEN :startIndex AND :endIndex " +
            "ORDER BY s.listIndex ASC")
    List<StatusListAvailableIndices> findAvailableIndicesInRange(
            @Param("credentialId") String statusListCredentialId,
            @Param("startIndex") Long startIndex,
            @Param("endIndex") Long endIndex);

    /**
     * Get indices usage statistics for a status list credential
     */
    @Query("SELECT NEW map(" +
            "SUM(CASE WHEN s.isAssigned = true THEN 1 ELSE 0 END) as assigned, " +
            "SUM(CASE WHEN s.isAssigned = false THEN 1 ELSE 0 END) as available, " +
            "COUNT(s) as total) " +
            "FROM StatusListAvailableIndices s WHERE s.statusListCredentialId = :credentialId")
    Object getIndicesStatistics(@Param("credentialId") String statusListCredentialId);

    /**
     * Delete all indices for a status list credential
     */
    @Modifying
    @Transactional
    void deleteByStatusListCredentialId(String statusListCredentialId);

    /**
     * Atomically claims a random available index using FOR UPDATE SKIP LOCKED
     * Returns the claimed index or null if none available
     */
    @Modifying
    @Query(value = """
        WITH available_slot AS (
            SELECT list_index
            FROM status_list_available_indices
            WHERE status_list_credential_id = :statusListCredentialId 
              AND is_assigned = FALSE
            ORDER BY RANDOM() 
            LIMIT 1
            FOR UPDATE SKIP LOCKED 
        )
        UPDATE status_list_available_indices sla
        SET is_assigned = TRUE,
            upd_dtimes = NOW() 
        FROM available_slot avs
        WHERE sla.status_list_credential_id = :statusListCredentialId
          AND sla.list_index = avs.list_index
          AND sla.is_assigned = FALSE 
        RETURNING sla.list_index
        """, nativeQuery = true)
    Long claimRandomAvailableIndex(@Param("statusListCredentialId") String statusListCredentialId);

    /**
     * Counts the number of available (unassigned) indices for a given status list
     */
    @Query(value = "SELECT COUNT(*) FROM status_list_available_indices WHERE status_list_credential_id = :statusListCredentialId AND is_assigned = FALSE", nativeQuery = true)
    long countAvailableIndices(@Param("statusListCredentialId") String statusListCredentialId);

    /**
     * Checks if a specific index is available for a given status list
     */
    @Query(value = "SELECT COUNT(*) > 0 FROM status_list_available_indices WHERE status_list_credential_id = :statusListCredentialId AND list_index = :index AND is_assigned = FALSE", nativeQuery = true)
    boolean isIndexAvailable(@Param("statusListCredentialId") String statusListCredentialId, @Param("index") Long index);

    /**
     * Releases an assigned index (marks it as available)
     */
    @Modifying
    @Query(value = "UPDATE status_list_available_indices SET is_assigned = FALSE, upd_dtimes = NOW() WHERE status_list_credential_id = :statusListCredentialId AND list_index = :index AND is_assigned = TRUE", nativeQuery = true)
    int releaseIndex(@Param("statusListCredentialId") String statusListCredentialId, @Param("index") Long index);

    /**
     * Find all indices for a status list by assignment status
     */
    List<StatusListAvailableIndices> findByStatusListCredentialIdAndIsAssigned(
            String statusListCredentialId, boolean isAssigned);

    /**
     * Find available indices with limit and random order
     */
    @Query(value = "SELECT * FROM status_list_available_indices " +
            "WHERE status_list_credential_id = :statusListCredentialId " +
            "AND is_assigned = false " +
            "ORDER BY RANDOM() " +
            "LIMIT :limit",
            nativeQuery = true)
    List<StatusListAvailableIndices> findRandomAvailableIndices(
            @Param("statusListCredentialId") String statusListCredentialId,
            @Param("limit") int limit);

    /**
     * Check if a specific index is assigned
     */
    @Query("SELECT sla.isAssigned FROM StatusListAvailableIndices sla " +
            "WHERE sla.statusListCredentialId = :statusListCredentialId " +
            "AND sla.listIndex = :listIndex")
    Optional<Boolean> isIndexAssigned(
            @Param("statusListCredentialId") String statusListCredentialId,
            @Param("listIndex") Long listIndex);

    /**
     * Get usage statistics for a status list
     */
    @Query("SELECT new map(" +
            "COUNT(*) as totalIndices, " +
            "SUM(CASE WHEN sla.isAssigned = true THEN 1 ELSE 0 END) as assignedIndices, " +
            "SUM(CASE WHEN sla.isAssigned = false THEN 1 ELSE 0 END) as availableIndices" +
            ") FROM StatusListAvailableIndices sla " +
            "WHERE sla.statusListCredentialId = :statusListCredentialId")
    Optional<java.util.Map<String, Object>> getUsageStatistics(
            @Param("statusListCredentialId") String statusListCredentialId);

    /**
     * Count assigned indices for a status list
     */
    @Query("SELECT COUNT(s) FROM StatusListAvailableIndices s WHERE s.statusListCredentialId = :listId AND s.isAssigned = true")
    long countAssignedIndices(@Param("listId") String listId);


    /**
     * Atomically claim an available index using skip locked approach
     */
    @Modifying
    @Query(value = """
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
        """, nativeQuery = true)
    Optional<Long> claimAvailableIndex(@Param("listId") String listId);

    /**
     * Bulk insert available indices for a new status list
     */
    @Modifying
    @Query(value = """
        INSERT INTO status_list_available_indices (status_list_credential_id, list_index, is_assigned, cr_dtimes)
        SELECT :listId, generate_series(0, :capacity - 1), false, NOW()
        """, nativeQuery = true)
    void populateAvailableIndices(@Param("listId") String listId, @Param("capacity") long capacity);
    /**
     * Count assigned indices for a status list
     */
    long countByStatusListCredentialIdAndIsAssigned(String statusListCredentialId, boolean isAssigned);

    /**
     * Atomically claim next available index using skip lock approach
     * This implements the Database Query Approach described in the requirements
     */
    @Modifying
    @Transactional
    @Query(value = """
        WITH available_slot AS (
            SELECT list_index
            FROM status_list_available_indices
            WHERE status_list_credential_id = :statusListId 
                AND is_assigned = FALSE
            ORDER BY RANDOM() 
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        )
        UPDATE status_list_available_indices sla
        SET is_assigned = TRUE,
            upd_dtimes = NOW()
        FROM available_slot avs
        WHERE sla.status_list_credential_id = :statusListId
            AND sla.list_index = avs.list_index
            AND sla.is_assigned = FALSE
        RETURNING sla.list_index
        """, nativeQuery = true)
    Optional<Long> claimNextAvailableIndex(@Param("statusListId") String statusListId);

    /**
     * Count assigned indices for a specific status list
     */
    long countByStatusListCredentialIdAndIsAssignedTrue(String statusListCredentialId);
}