package io.mosip.certify.services;

import io.mosip.certify.api.dto.RenderingTemplateDTO;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.services.entity.RenderingTemplate;
import io.mosip.certify.core.exception.RenderingTemplateException;
import io.mosip.certify.services.repository.RenderingTemplateRepository;
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

@Slf4j
@RunWith(MockitoJUnitRunner.class)
public class RenderingTemplateServiceImplTest {
    @InjectMocks
    RenderingTemplateServiceImpl renderingTemplateService;

    @Mock
    RenderingTemplateRepository svgRenderTemplateRepository;

    @Test
    public void getSvgTemplate_withValidDetail_thenPass() {
        RenderingTemplate svgRenderTemplate = new RenderingTemplate();
        svgRenderTemplate.setId("fake-id");
        String svgTemplate = """
                    <svg xmlns=\\"http://www.w3.org/2000/svg\\" width=\\"200\\" height=\\"200\\">
                    <rect width=\\"200\\" height=\\"200\\" fill=\\"#ff6347\\"/>
                    <text x=\\"100\\" y=\\"100\\" font-size=\\"30\\" text-anchor=\\"middle\\" fill=\\"white\\">
                    Hello, SVG!
                    </text></svg>
                """;
        svgRenderTemplate.setTemplate(svgTemplate);
        svgRenderTemplate.setCreatedtimes(LocalDateTime.now());
        Optional<RenderingTemplate> optional = Optional.of(svgRenderTemplate);
        Mockito.when(svgRenderTemplateRepository.findById(Mockito.any())).thenReturn(optional);
        RenderingTemplateDTO svgRenderTemplateResponse = renderingTemplateService.getSvgTemplate("fake-id");
        Assert.assertNotNull(svgRenderTemplateResponse);
        Assert.assertEquals(svgRenderTemplate.getId(), svgRenderTemplateResponse.getId());
        Assert.assertEquals(svgTemplate, optional.get().getTemplate());
    }

    @Test
    public void getSvgTemplate_withInvalidId_thenFail() {
        Mockito.when(svgRenderTemplateRepository.findById(Mockito.any())).thenReturn(Optional.empty());
        RenderingTemplateException templateException = Assert.assertThrows(RenderingTemplateException.class, () -> {
            renderingTemplateService.getSvgTemplate("fake-id");
        });
        Assert.assertEquals(ErrorConstants.INVALID_TEMPLATE_ID, templateException.getErrorCode());
    }

}
