package io.mosip.certify.services;

import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.utils.BitStringStatusListUtils;
import net.javacrumbs.shedlock.core.LockAssert;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.data.domain.Pageable;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class StatusListUpdateBatchJobTest {

    @Mock
    private CredentialStatusTransactionRepository transactionRepository;

    @Mock
    private StatusListCredentialRepository statusListRepository;

    @Mock
    private StatusListCredentialService statusListCredentialService;

    @Mock
    private PlatformTransactionManager transactionManager;

    @Mock
    private TransactionStatus transactionStatus;

    private StatusListUpdateBatchJob batchJob;

    @Before
    public void setup() {
        batchJob = spy(new StatusListUpdateBatchJob(transactionRepository, statusListRepository,
                statusListCredentialService, new TransactionTemplate(transactionManager)));
        LockAssert.TestHelper.makeAllAssertsPass(true);
        ReflectionTestUtils.setField(batchJob, "batchJobEnabled", true);
        ReflectionTestUtils.setField(batchJob, "batchSize", 1000);
    }

    @After
    public void tearDown() {
        LockAssert.TestHelper.makeAllAssertsPass(false);
    }

    private CredentialStatusTransaction txn(String listId, long index, boolean value) {
        CredentialStatusTransaction txn = new CredentialStatusTransaction();
        txn.setStatusListCredentialId(listId);
        txn.setStatusListIndex(index);
        txn.setStatusValue(value);
        txn.setCreatedDtimes(LocalDateTime.now());
        return txn;
    }

    @Test
    public void should_returnEarly_when_batchJobIsDisabled() {
        ReflectionTestUtils.setField(batchJob, "batchJobEnabled", false);
        batchJob.updateStatusLists();
        verify(transactionRepository, never()).findByIsProcessedFalseOrderByCreatedDtimesAsc(any());
    }

    @Test
    public void should_returnEarly_when_noTransactionsExist() {
        when(transactionRepository.findByIsProcessedFalseOrderByCreatedDtimesAsc(any(Pageable.class)))
                .thenReturn(Collections.emptyList());
        batchJob.updateStatusLists();
        verify(statusListRepository, never()).findById(anyString());
    }

    @Test
    public void should_processGroups_when_transactionsExist() {
        List<CredentialStatusTransaction> txns = List.of(
                txn("list-a", 1L, true), txn("list-a", 2L, true), txn("list-b", 1L, true));
        when(transactionRepository.findByIsProcessedFalseOrderByCreatedDtimesAsc(any(Pageable.class)))
                .thenReturn(txns);
        doNothing().when(batchJob).updateStatusList(anyString(), anyList());

        batchJob.updateStatusLists();

        verify(batchJob).updateStatusList(eq("list-a"), anyList());
        verify(batchJob).updateStatusList(eq("list-b"), anyList());
    }

    @Test
    public void should_updateEachStatusListInItsOwnTransaction_when_oneGroupFails() {
        // updateStatusList is called on this, so only the template can give it a transaction:
        // a failed list is rolled back on its own and the other list still commits.
        List<CredentialStatusTransaction> txns = List.of(txn("list-a", 1L, true), txn("list-b", 1L, true));
        when(transactionRepository.findByIsProcessedFalseOrderByCreatedDtimesAsc(any(Pageable.class)))
                .thenReturn(txns);
        when(transactionManager.getTransaction(any())).thenReturn(transactionStatus);
        doThrow(new RuntimeException("fail")).when(batchJob).updateStatusList(eq("list-a"), anyList());
        doNothing().when(batchJob).updateStatusList(eq("list-b"), anyList());

        batchJob.updateStatusLists();

        verify(transactionManager, times(2)).getTransaction(any());
        verify(transactionManager).rollback(transactionStatus);
        verify(transactionManager).commit(transactionStatus);
    }

    @Test
    public void should_continueProcessing_when_oneGroupFails() {
        List<CredentialStatusTransaction> txns = List.of(txn("list-a", 1L, true), txn("list-b", 1L, true));
        when(transactionRepository.findByIsProcessedFalseOrderByCreatedDtimesAsc(any(Pageable.class)))
                .thenReturn(txns);
        doThrow(new RuntimeException("fail")).when(batchJob).updateStatusList(eq("list-a"), anyList());
        doNothing().when(batchJob).updateStatusList(eq("list-b"), anyList());

        batchJob.updateStatusLists();

        verify(batchJob).updateStatusList(eq("list-b"), anyList());
    }

    @Test
    public void should_wrapInCertifyException_when_fetchThrows() {
        when(transactionRepository.findByIsProcessedFalseOrderByCreatedDtimesAsc(any(Pageable.class)))
                .thenThrow(new RuntimeException("db error"));
        assertThrows(CertifyException.class, () -> batchJob.updateStatusLists());
    }

    @Test
    public void should_throwCertifyException_when_statusListNotFound() {
        when(statusListRepository.findById("list-a")).thenReturn(Optional.empty());
        assertThrows(CertifyException.class, () ->
                batchJob.updateStatusList("list-a", List.of(txn("list-a", 1L, true))));
    }

    @Test
    public void should_markProcessedAndSave_when_updateSucceeds() {
        long capacityKb = 1L;
        String encoded = BitStringStatusListUtils.createEmptyEncodedList(capacityKb);
        JSONObject credentialSubject = new JSONObject().put("encodedList", encoded);
        JSONObject vc = new JSONObject().put("credentialSubject", credentialSubject);

        StatusListCredential list = new StatusListCredential();
        list.setId("list-a");
        list.setCapacityInKB(capacityKb);
        list.setVcDocument(vc.toString());

        when(statusListRepository.findById("list-a")).thenReturn(Optional.of(list));
        when(statusListCredentialService.resignStatusListCredential(anyString())).thenReturn(vc.toString());

        batchJob.updateStatusList("list-a", List.of(txn("list-a", 1L, true), txn("list-a", 1L, false)));

        verify(transactionRepository).saveAll(anyList());
        verify(statusListRepository, atLeastOnce()).save(list);
    }

    @Test
    public void should_returnUpdatedCredential_when_updateSucceeds() {
        JSONObject credentialSubject = new JSONObject().put("encodedList", "abc");
        JSONObject vc = new JSONObject().put("credentialSubject", credentialSubject);

        StatusListCredential list = new StatusListCredential();
        list.setId("list-a");
        list.setVcDocument(vc.toString());

        when(statusListCredentialService.resignStatusListCredential(anyString())).thenReturn(vc.toString());

        batchJob.updateStatusListCredential(list, "newEncodedList");

        verify(statusListRepository).save(list);
    }

    @Test
    public void should_throwCertifyException_when_vcDocumentIsInvalidJson() {
        StatusListCredential list = new StatusListCredential();
        list.setId("list-a");
        list.setVcDocument("{invalid json");
        assertThrows(CertifyException.class, () ->
                batchJob.updateStatusListCredential(list, "newEncodedList"));
    }
}
