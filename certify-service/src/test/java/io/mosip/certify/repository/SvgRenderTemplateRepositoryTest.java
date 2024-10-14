package io.mosip.certify.repository;

import io.mosip.certify.core.entity.SvgRenderTemplate;
import io.mosip.certify.core.repository.SvgRenderTemplateRepository;
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

@RunWith(SpringRunner.class)
@DataJpaTest
public class SvgRenderTemplateRepositoryTest {
    @Autowired
    private SvgRenderTemplateRepository svgRenderTemplateRepository;

    @Test
    public void insertSvgTemplate_withValidDetail_thenPass() {
        SvgRenderTemplate svgRenderTemplate = new SvgRenderTemplate();
        String svgTemplate = """
                    <svg xmlns=\\"http://www.w3.org/2000/svg\\" width=\\"200\\" height=\\"200\\">
                    <rect width=\\"200\\" height=\\"200\\" fill=\\"#ff6347\\"/>
                    <text x=\\"100\\" y=\\"100\\" font-size=\\"30\\" text-anchor=\\"middle\\" fill=\\"white\\">
                    Hello, SVG!
                    </text></svg>
                """;
        svgRenderTemplate.setId("TestSvgTemplate");
        svgRenderTemplate.setSvgTemplate(svgTemplate);
        svgRenderTemplate.setLastModified(LocalDateTime.now());

        svgRenderTemplate = svgRenderTemplateRepository.saveAndFlush(svgRenderTemplate);
        Assert.assertNotNull(svgRenderTemplate);

        Optional<SvgRenderTemplate> optional = svgRenderTemplateRepository.findById(svgRenderTemplate.getId());
        Assert.assertTrue(optional.isPresent());
    }

    @Test
    public void insertSvgTemplate_withInvalidId_thenFail() {
        SvgRenderTemplate svgRenderTemplate = new SvgRenderTemplate();
        String svgTemplate = """
                    <svg xmlns=\\"http://www.w3.org/2000/svg\\" width=\\"200\\" height=\\"200\\">
                    <rect width=\\"200\\" height=\\"200\\" fill=\\"#ff6347\\"/>
                    <text x=\\"100\\" y=\\"100\\" font-size=\\"30\\" text-anchor=\\"middle\\" fill=\\"white\\">
                    Hello, SVG!
                    </text></svg>
                """;
        svgRenderTemplate.setId("");
        svgRenderTemplate.setSvgTemplate(svgTemplate);
        svgRenderTemplate.setLastModified(LocalDateTime.now());

        ConstraintViolationException e = Assertions.assertThrows(
                ConstraintViolationException.class, () -> svgRenderTemplateRepository.saveAndFlush(svgRenderTemplate)
        );

        Assert.assertTrue(e.getConstraintViolations().stream()
                .anyMatch( v -> v.getPropertyPath().toString().equals("id")));
    }

    @Test
    public void insertSvgTemplate_withEmptyTemplate_thenFail() {
        SvgRenderTemplate svgRenderTemplate = new SvgRenderTemplate();
        svgRenderTemplate.setId("TestSvgTemplate");
        svgRenderTemplate.setSvgTemplate("");
        svgRenderTemplate.setLastModified(LocalDateTime.now());

        ConstraintViolationException e = Assertions.assertThrows(
                ConstraintViolationException.class, () -> svgRenderTemplateRepository.saveAndFlush(svgRenderTemplate)
        );

        Assert.assertTrue(e.getConstraintViolations().stream()
                .anyMatch( v -> v.getPropertyPath().toString().equals("svgTemplate")));
    }
}
