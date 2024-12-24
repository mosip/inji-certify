package io.mosip.certify.repository;

import io.mosip.certify.entity.CredentialTemplate;
import io.mosip.certify.entity.RenderingTemplate;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.time.LocalDateTime;
import java.util.Optional;

@RunWith(SpringRunner.class)
@DataJpaTest
public class CredentialTemplateRepositoryTest {
    @Autowired
    private CredentialTemplateRepository credentialTemplateRepository;

    private CredentialTemplate credentialTemplate;

    @Before
    public void setup() {
        credentialTemplate = new CredentialTemplate();
        String template = "test-template";
        credentialTemplate.setTemplate(template);
        credentialTemplate.setCredentialType("MockVerifiableCredential,VerifiableCredential");
        credentialTemplate.setContext("https://www.example.com");
        credentialTemplate.setCreatedTimes(LocalDateTime.now());
        credentialTemplate = credentialTemplateRepository.saveAndFlush(credentialTemplate);
    }

    @Test
    public void findByValidCredentialTypeAndContext_thenPass() {
        Assert.assertNotNull(credentialTemplate);
        Optional<CredentialTemplate> optional = credentialTemplateRepository.findByCredentialTypeAndContext(credentialTemplate.getCredentialType(), credentialTemplate.getContext());
        Assert.assertTrue(optional.isPresent());
        Assert.assertEquals(credentialTemplate.getTemplate(), optional.get().getTemplate());
    }

    @Test
    public void findByInvalidCredentialTypeAndContext_thenFail() {
        Assert.assertNotNull(credentialTemplate);

        String requestedCredentialType = "TestCredential,VerifiableCredential";
        Optional<CredentialTemplate> optional = credentialTemplateRepository.findByCredentialTypeAndContext(requestedCredentialType, credentialTemplate.getContext());
        Assert.assertTrue(optional.isEmpty());
    }
}
