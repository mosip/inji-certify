package io.mosip.certify.repository;

import io.mosip.certify.core.entity.SvgTemplate;
import io.mosip.certify.core.repository.SvgTemplateRepository;
import jakarta.validation.ConstraintViolationException;
import org.junit.Assert;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@RunWith(SpringRunner.class)
@DataJpaTest
public class SvgRenderTemplateRepositoryTest {
    @Autowired
    private SvgTemplateRepository svgRenderTemplateRepository;

    @Test
    public void insertSvgTemplate_withValidDetail_thenPass() {
        SvgTemplate svgRenderTemplate = new SvgTemplate();
        String template = """
                    <svg xmlns=\\"http://www.w3.org/2000/svg\\" width=\\"200\\" height=\\"200\\">
                    <rect width=\\"200\\" height=\\"200\\" fill=\\"#ff6347\\"/>
                    <text x=\\"100\\" y=\\"100\\" font-size=\\"30\\" text-anchor=\\"middle\\" fill=\\"white\\">
                    Hello, SVG!
                    </text></svg>
                """;
        UUID id = UUID.randomUUID();
        svgRenderTemplate.setId(id);
        svgRenderTemplate.setTemplate(template);
        svgRenderTemplate.setCreatedtimes(LocalDateTime.now());

        svgRenderTemplate = svgRenderTemplateRepository.saveAndFlush(svgRenderTemplate);
        Assert.assertNotNull(svgRenderTemplate);

        Optional<SvgTemplate> optional = svgRenderTemplateRepository.findById(svgRenderTemplate.getId());
        Assert.assertTrue(optional.isPresent());
        Assert.assertEquals(svgRenderTemplate.getTemplate(), optional.get().getTemplate());
    }

    @Test
    public void insertSvgTemplate_withEmptyTemplate_thenFail() {
        SvgTemplate svgRenderTemplate = new SvgTemplate();
        svgRenderTemplate.setId(UUID.randomUUID());
        svgRenderTemplate.setTemplate("");
        svgRenderTemplate.setCreatedtimes(LocalDateTime.now());

        ConstraintViolationException e = Assertions.assertThrows(
                ConstraintViolationException.class, () -> svgRenderTemplateRepository.saveAndFlush(svgRenderTemplate)
        );

        Assert.assertTrue(e.getConstraintViolations().stream()
                .anyMatch( v -> v.getPropertyPath().toString().equals("template")));
    }
}
