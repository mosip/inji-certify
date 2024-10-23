package io.mosip.certify.services;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.entity.SvgTemplate;
import io.mosip.certify.core.exception.TemplateException;
import io.mosip.certify.core.repository.SvgTemplateRepository;
import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@RunWith(MockitoJUnitRunner.class)
public class SvgRenderTemplateServiceTest {
    @InjectMocks
    SvgTemplateServiceImpl svgRenderTemplateService;

    @Mock
    SvgTemplateRepository svgRenderTemplateRepository;

    @Test
    public void getSvgTemplate_withValidDetail_thenPass() {
        SvgTemplate svgRenderTemplate = new SvgTemplate();
        UUID id = UUID.randomUUID();
        svgRenderTemplate.setId(id);
        String svgTemplate = """
                    <svg xmlns=\\"http://www.w3.org/2000/svg\\" width=\\"200\\" height=\\"200\\">
                    <rect width=\\"200\\" height=\\"200\\" fill=\\"#ff6347\\"/>
                    <text x=\\"100\\" y=\\"100\\" font-size=\\"30\\" text-anchor=\\"middle\\" fill=\\"white\\">
                    Hello, SVG!
                    </text></svg>
                """;
        svgRenderTemplate.setTemplate(svgTemplate);
        svgRenderTemplate.setCreatedtimes(LocalDateTime.now());
        Optional<SvgTemplate> optional = Optional.of(svgRenderTemplate);
        Mockito.when(svgRenderTemplateRepository.findById(Mockito.any())).thenReturn(optional);
        SvgTemplate svgRenderTemplateResponse = svgRenderTemplateService.getSvgTemplate(UUID.randomUUID());
        Assert.assertNotNull(svgRenderTemplateResponse);
        Assert.assertEquals(svgRenderTemplate.getId(), svgRenderTemplateResponse.getId());
        Assert.assertEquals(svgTemplate, optional.get().getTemplate());
    }

    @Test
    public void getSvgTemplate_withInvalidId_thenFail() {
        Mockito.when(svgRenderTemplateRepository.findById(Mockito.any())).thenReturn(Optional.empty());
        TemplateException templateException = Assert.assertThrows(TemplateException.class, () -> {
            svgRenderTemplateService.getSvgTemplate(UUID.randomUUID());
        });
        Assert.assertEquals(ErrorConstants.INVALID_TEMPLATE_ID, templateException.getErrorCode());
    }

}
