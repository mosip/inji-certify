/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
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
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.data.domain.Pageable;
import org.springframework.test.util.ReflectionTestUtils;

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

    @Spy
    @InjectMocks
    private StatusListUpdateBatchJob batchJob;

    @Before
    public void setup() {
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
    public void updateStatusLists_disabled_returnsEarly() {
        ReflectionTestUtils.setField(batchJob, "batchJobEnabled", false);
        batchJob.updateStatusLists();
        verify(transactionRepository, never()).findByIsProcessedFalseOrderByCreatedDtimesAsc(any());
    }

    @Test
    public void updateStatusLists_noTransactions_returns() {
        when(transactionRepository.findByIsProcessedFalseOrderByCreatedDtimesAsc(any(Pageable.class)))
                .thenReturn(Collections.emptyList());
        batchJob.updateStatusLists();
        verify(statusListRepository, never()).findById(anyString());
    }

    @Test
    public void updateStatusLists_processesGroups() {
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
    public void updateStatusLists_oneGroupFails_continues() {
        List<CredentialStatusTransaction> txns = List.of(txn("list-a", 1L, true), txn("list-b", 1L, true));
        when(transactionRepository.findByIsProcessedFalseOrderByCreatedDtimesAsc(any(Pageable.class)))
                .thenReturn(txns);
        doThrow(new RuntimeException("fail")).when(batchJob).updateStatusList(eq("list-a"), anyList());
        doNothing().when(batchJob).updateStatusList(eq("list-b"), anyList());

        batchJob.updateStatusLists();

        verify(batchJob).updateStatusList(eq("list-b"), anyList());
    }

    @Test
    public void updateStatusLists_fetchThrows_wrapsInCertifyException() {
        when(transactionRepository.findByIsProcessedFalseOrderByCreatedDtimesAsc(any(Pageable.class)))
                .thenThrow(new RuntimeException("db error"));
        assertThrows(CertifyException.class, () -> batchJob.updateStatusLists());
    }

    @Test
    public void updateStatusList_notFound_throws() {
        when(statusListRepository.findById("list-a")).thenReturn(Optional.empty());
        assertThrows(CertifyException.class, () ->
                batchJob.updateStatusList("list-a", List.of(txn("list-a", 1L, true))));
    }

    @Test
    public void updateStatusList_success_marksProcessedAndSaves() {
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
    public void updateStatusListCredential_success() {
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
    public void updateStatusListCredential_invalidJson_throws() {
        StatusListCredential list = new StatusListCredential();
        list.setId("list-a");
        list.setVcDocument("{invalid json");
        assertThrows(CertifyException.class, () ->
                batchJob.updateStatusListCredential(list, "newEncodedList"));
    }
}
