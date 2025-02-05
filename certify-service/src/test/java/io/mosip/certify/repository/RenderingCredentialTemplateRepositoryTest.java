package io.mosip.certify.repository;

import io.mosip.certify.entity.RenderingTemplate;
import jakarta.validation.ConstraintViolationException;
import org.junit.Assert;
import org.junit.Before;
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
public class RenderingCredentialTemplateRepositoryTest {
    @Autowired
    private RenderingTemplateRepository svgRenderTemplateRepository;

    LocalDateTime localDateTime;

    @Before
    public void setup() {
        localDateTime = LocalDateTime.now();
    }

    @Test
    public void insertSvgTemplate_withValidDetail_thenPass() {
        RenderingTemplate svgRenderTemplate = new RenderingTemplate();
        String template = """
                    <svg xmlns=\\"http://www.w3.org/2000/svg\\" width=\\"200\\" height=\\"200\\">
                    <rect width=\\"200\\" height=\\"200\\" fill=\\"#ff6347\\"/>
                    <text x=\\"100\\" y=\\"100\\" font-size=\\"30\\" text-anchor=\\"middle\\" fill=\\"white\\">
                    Hello, SVG!
                    </text></svg>
                """;
        svgRenderTemplate.setId("fake-id");
        svgRenderTemplate.setTemplate(template);
        svgRenderTemplate.setCreatedtimes(localDateTime);
        svgRenderTemplate.setUpdatedtimes(localDateTime);

        svgRenderTemplate = svgRenderTemplateRepository.saveAndFlush(svgRenderTemplate);
        Assert.assertNotNull(svgRenderTemplate);

        Optional<RenderingTemplate> optional = svgRenderTemplateRepository.findById(svgRenderTemplate.getId());
        Assert.assertTrue(svgRenderTemplate.equals(optional.get()));
        Assert.assertTrue(svgRenderTemplate.toString().equals(optional.get().toString()));
        Assert.assertEquals(optional.get().hashCode(), svgRenderTemplate.hashCode());
        Assert.assertTrue(optional.isPresent());
        Assert.assertEquals(svgRenderTemplate.getTemplate(), optional.get().getTemplate());
    }

    @Test
    public void insertSvgTemplate_withEmptyTemplate_thenFail() {
        RenderingTemplate svgRenderTemplate = new RenderingTemplate();
        svgRenderTemplate.setId("fake-id");
        svgRenderTemplate.setTemplate("");
        localDateTime = LocalDateTime.now();
        svgRenderTemplate.setCreatedtimes(localDateTime);
        svgRenderTemplate.setUpdatedtimes(localDateTime);

        ConstraintViolationException e = Assertions.assertThrows(
                ConstraintViolationException.class, () -> svgRenderTemplateRepository.saveAndFlush(svgRenderTemplate)
        );

        Assert.assertTrue(e.getConstraintViolations().stream()
                .anyMatch( v -> v.getPropertyPath().toString().equals("template")));
    }
}
