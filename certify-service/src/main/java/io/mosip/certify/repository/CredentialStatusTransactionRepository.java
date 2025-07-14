package io.mosip.certify.repository;

import io.mosip.certify.entity.CredentialStatusTransaction;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface CredentialStatusTransactionRepository extends JpaRepository<CredentialStatusTransaction, Long> {

    /**
     * Find all transactions created since the given timestamp, ordered by creation time
     * Limited by the specified batch size
     */
    @Query("SELECT t FROM CredentialStatusTransaction t WHERE t.createdDtimes > :since ORDER BY t.createdDtimes ASC")
    List<CredentialStatusTransaction> findTransactionsSince(@Param("since") LocalDateTime since, Pageable pageable);

    /**
     * Convenience method for batch processing
     */
    default List<CredentialStatusTransaction> findTransactionsSince(LocalDateTime since, int batchSize) {
        return findTransactionsSince(since, PageRequest.of(0, batchSize));
    }

    /**
     * Find the latest status transaction for each credential in a specific status list
     * This helps to get the current state of all credentials in a status list
     */
    @Query("SELECT t FROM CredentialStatusTransaction t WHERE t.statusListCredentialId = :statusListId ORDER BY t.credentialId, t.createdDtimes DESC")
    List<CredentialStatusTransaction> findLatestStatusByStatusListId(@Param("statusListId") String statusListId);

    Optional<CredentialStatusTransaction> findByCredentialId(String credentialId);
}