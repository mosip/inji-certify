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

    /**
     * Count assigned indices for a specific status list
     */
    long countByStatusListCredentialIdAndIsAssignedTrue(String statusListCredentialId);
}