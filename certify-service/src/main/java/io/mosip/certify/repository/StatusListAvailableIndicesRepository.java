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
    long countByStatusListCredentialIdAndIsAssignedTrue(String statusListCredentialId);
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
     * Release an index (mark as available)
     */
    @Modifying
    @Transactional
    @Query("UPDATE StatusListAvailableIndices s SET s.isAssigned = false, s.updatedDtimes = CURRENT_TIMESTAMP " +
            "WHERE s.statusListCredentialId = :credentialId AND s.listIndex = :index")
    int releaseIndex(@Param("credentialId") String statusListCredentialId, @Param("index") Long listIndex);

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
}