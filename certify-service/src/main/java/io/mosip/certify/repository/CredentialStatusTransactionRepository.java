package io.mosip.certify.repository;

import io.mosip.certify.entity.CredentialStatusTransaction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Repository for the credential_status_transaction table
 */
@Repository
public interface CredentialStatusTransactionRepository extends JpaRepository<CredentialStatusTransaction, Long> {

    /**
     * Find all transactions that occurred after a specified timestamp
     *
     * @param timestamp the timestamp to filter transactions
     * @return list of transactions created after the specified timestamp
     */
    @Query("SELECT cst FROM CredentialStatusTransaction cst WHERE cst.createdDtimes > :timestamp ORDER BY cst.createdDtimes ASC")
    List<CredentialStatusTransaction> findTransactionsSince(@Param("timestamp") LocalDateTime timestamp);

    /**
     * Find all transactions for a specific credential
     *
     * @param credentialId the ID of the credential
     * @return list of transactions for the specified credential
     */
    List<CredentialStatusTransaction> findByCredentialId(String credentialId);

    /**
     * Find all transactions for a specific status list credential
     *
     * @param statusListCredentialId the ID of the status list credential
     * @return list of transactions for the specified status list credential
     */
    List<CredentialStatusTransaction> findByStatusListCredentialId(String statusListCredentialId);

    /**
     * Find transactions created after the specified timestamp
     *
     * @param timestamp the timestamp to compare against
     * @return list of transactions created after the specified timestamp
     */
    List<CredentialStatusTransaction> findByCreatedDtimesAfterOrderByCreatedDtimes(LocalDateTime timestamp);
}