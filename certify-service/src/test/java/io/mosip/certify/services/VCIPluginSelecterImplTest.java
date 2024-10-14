package io.mosip.certify.services;

import io.mosip.certify.api.dto.VCRequestDto;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Set;

@RunWith(MockitoJUnitRunner.class)
public class VCIPluginSelecterImplTest {

    @InjectMocks
    VCIPluginSelecterImpl vciPluginSelecter;

    @Before
    public void setUp() throws Exception {
        vciPluginSelecter = new VCIPluginSelecterImpl();
        ReflectionTestUtils.setField(vciPluginSelecter, "dataProviderPluginCredentialTypes", Set.of("SchoolCredential","UniversityCredential"));
    }

    @Test
    public void choosePlugin_DataProviderPlugin() {
        VCRequestDto v = new VCRequestDto();
        v.setType(List.of("VerifiableCredential", "SchoolCredential"));
        PluginType original = vciPluginSelecter.choosePlugin(v);
        Assert.assertEquals(original, PluginType.DataProviderPlugin);
    }

    @Test
    public void choosePlugin_VCIssuancePlugin() {
        VCRequestDto v = new VCRequestDto();
        v.setType(List.of("VerifiableCredential", "NationalIdentity"));
        PluginType original = vciPluginSelecter.choosePlugin(v);
        Assert.assertEquals(original, PluginType.VCIssuancePlugin);
    }
}