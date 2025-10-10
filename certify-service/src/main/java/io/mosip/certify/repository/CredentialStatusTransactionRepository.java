package io.mosip.certify.repository;

import io.mosip.certify.entity.CredentialStatusTransaction;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface CredentialStatusTransactionRepository extends JpaRepository<CredentialStatusTransaction, Long> {

    /**
     * Find a batch of unprocessed transactions, ordered by creation time, with custom batch size.
     */
    List<CredentialStatusTransaction> findByIsProcessedFalseOrderByCreatedDtimesAsc(Pageable pageable);
}