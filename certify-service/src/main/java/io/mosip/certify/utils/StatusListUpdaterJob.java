package io.mosip.certify.utils;

import io.mosip.certify.entity.CredentialStatus;
import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.CredentialStatusRepository;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.services.StatusListCredentialService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Job to update the status list credentials based on credential status transactions
 * This job runs at configurable intervals to process new status transactions and
 * regenerate the relevant status list credentials
 */
@Slf4j
@Component
public class StatusListUpdaterJob {

    @Autowired
    private CredentialStatusTransactionRepository transactionRepository;

    @Autowired
    private CredentialStatusRepository credentialStatusRepository;

    @Autowired
    private StatusListCredentialRepository statusListCredentialRepository;

    @Autowired
    private StatusListCredentialService statusListCredentialService;

    @Value("${mosip.certify.status-list-update.job.lock-timeout-seconds:300}")
    private int lockTimeoutSeconds;

    @Value("${mosip.certify.status-list-update.job.batch-size:100}")
    private int batchSize;

    private LocalDateTime lastProcessedTimestamp = LocalDateTime.now().minusYears(10); // Default to a past date

    /**
     * Scheduled method that runs at a configurable interval to process credential status transactions
     * and update status list credentials accordingly
     */
    @Scheduled(fixedDelayString = "${mosip.certify.status-list-update.job.interval-ms:3600000}")
    public void processStatusUpdates() {
        log.info("Starting status list update job at {}", LocalDateTime.now());

        try {
            List<CredentialStatusTransaction> newTransactions = fetchNewTransactions();

            if (newTransactions.isEmpty()) {
                log.info("No new transactions found. Exiting job.");
                return;
            }

            log.info("Found {} new transactions to process", newTransactions.size());

            // Process transactions in batches to avoid memory issues with large datasets
            List<List<CredentialStatusTransaction>> batches = getBatches(newTransactions, batchSize);

            for (List<CredentialStatusTransaction> batch : batches) {
                processTransactionBatch(batch);
            }

            updateLastProcessedTimestamp(newTransactions);

            log.info("Status list update job completed successfully at {}", LocalDateTime.now());
        } catch (Exception e) {
            log.error("Error occurred while processing status updates", e);
        }
    }

    /**
     * Fetch new transactions that haven't been processed yet
     *
     * @return List of new CredentialStatusTransaction objects
     */
    private List<CredentialStatusTransaction> fetchNewTransactions() {
        log.debug("Fetching transactions created after {}", lastProcessedTimestamp);
        return transactionRepository.findByCreatedDtimesAfterOrderByCreatedDtimes(lastProcessedTimestamp);
    }

    /**
     * Process a batch of transactions
     *
     * @param transactions List of transactions to process
     */
    @Transactional
    public void processTransactionBatch(List<CredentialStatusTransaction> transactions) {
        Set<String> affectedStatusListIds = new HashSet<>();

        for (CredentialStatusTransaction transaction : transactions) {
            try {
                updateCredentialStatus(transaction);

                if (transaction.getStatusListCredentialId() != null) {
                    affectedStatusListIds.add(transaction.getStatusListCredentialId());
                }
            } catch (Exception e) {
                log.error("Error processing transaction for credential ID: {}", transaction.getCredentialId(), e);
            }
        }

        regenerateAffectedStatusLists(affectedStatusListIds);
    }

    /**
     * Update the credential status with transaction data using pessimistic locking
     *
     * @param transaction The transaction data to apply
     */
    private void updateCredentialStatus(CredentialStatusTransaction transaction) {
        // Find credential status record with lock for update
        Optional<CredentialStatus> statusOpt = credentialStatusRepository.findByCredentialIdForUpdate(transaction.getCredentialId());

        if (statusOpt.isPresent()) {
            CredentialStatus status = statusOpt.get();

            // Update status with transaction data
            if (transaction.getStatusPurpose() != null) {
                status.setStatusPurpose(transaction.getStatusPurpose());
            }

            // Update status value if provided
            if (transaction.getStatusValue() != null) {
                status.setStatusValue(transaction.getStatusValue() ? "revoked" : "valid");
            }

            // Update status list credential ID and index if provided
            if (transaction.getStatusListCredentialId() != null) {
                status.setStatusListCredentialId(transaction.getStatusListCredentialId());
            }

            if (transaction.getStatusListIndex() != null) {
                status.setStatusListIndex(transaction.getStatusListIndex());
            }

            // Update timestamp
            status.setUpdatedDtimes(LocalDateTime.now());

            // Save updated status
            credentialStatusRepository.save(status);
            log.debug("Updated credential status for credential ID: {}", transaction.getCredentialId());
        } else {
            log.warn("No credential status found for credential ID: {}", transaction.getCredentialId());
        }
    }

    /**
     * Regenerate affected status lists
     *
     * @param affectedStatusListIds Set of status list IDs that need to be regenerated
     */
    private void regenerateAffectedStatusLists(Set<String> affectedStatusListIds) {
        log.info("Regenerating {} affected status lists", affectedStatusListIds.size());

        for (String statusListId : affectedStatusListIds) {
            try {
                Optional<StatusListCredential> statusListOpt = statusListCredentialRepository.findById(statusListId);

                if (statusListOpt.isPresent()) {
                    StatusListCredential statusList = statusListOpt.get();

                    List<CredentialStatus> statusEntries = credentialStatusRepository.findByStatusListCredentialId(statusListId);

                    Map<Long, Boolean> statusMap = statusEntries.stream()
                            .filter(entry -> entry.getStatusListIndex() != null)
                            .collect(Collectors.toMap(
                                    CredentialStatus::getStatusListIndex,
                                    entry -> "revoked".equals(entry.getStatusValue())
                            ));

                    regenerateStatusListCredential(statusList, statusMap);

                    log.info("Successfully regenerated status list credential: {}", statusListId);
                } else {
                    log.warn("Status list credential not found with ID: {}", statusListId);
                }
            } catch (Exception e) {
                log.error("Error regenerating status list credential: {}", statusListId, e);
            }
        }
    }

    /**
     * Regenerate a status list credential with updated bitstring
     *
     * @param statusList The status list credential to update
     * @param statusMap Map of index to status value (true for revoked, false for valid)
     */
    private void regenerateStatusListCredential(StatusListCredential statusList, Map<Long, Boolean> statusMap) {
        for (Map.Entry<Long, Boolean> entry : statusMap.entrySet()) {
            statusListCredentialService.updateStatusAtIndex(statusList.getId(), entry.getKey(), entry.getValue());
        }
    }

    /**
     * Split a list into batches of specified size
     *
     * @param list The list to split
     * @param batchSize The maximum size of each batch
     * @return List of batches
     */
    private <T> List<List<T>> getBatches(List<T> list, int batchSize) {
        List<List<T>> batches = new ArrayList<>();
        for (int i = 0; i < list.size(); i += batchSize) {
            batches.add(list.subList(i, Math.min(i + batchSize, list.size())));
        }
        return batches;
    }

    /**
     * Update the last processed timestamp based on the transactions processed
     *
     * @param transactions The transactions that were processed
     */
    private void updateLastProcessedTimestamp(List<CredentialStatusTransaction> transactions) {
        Optional<LocalDateTime> latestTimestamp = transactions.stream()
                .map(CredentialStatusTransaction::getCreatedDtimes)
                .max(LocalDateTime::compareTo);

        latestTimestamp.ifPresent(timestamp -> {
            lastProcessedTimestamp = timestamp;
            log.debug("Updated last processed timestamp to {}", lastProcessedTimestamp);
        });
    }
}