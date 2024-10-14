package io.mosip.certify.services;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.SvgRenderTemplateDto;
import io.mosip.certify.core.entity.SvgRenderTemplate;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.repository.SvgRenderTemplateRepository;
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
    SvgRenderTemplateServiceImpl svgRenderTemplateService;

    @Mock
    SvgRenderTemplateRepository svgRenderTemplateRepository;

    @Test
    public void getSvgTemplate_withValidDetail_thenPass() {
        SvgRenderTemplate svgRenderTemplate = new SvgRenderTemplate();
        UUID id = UUID.randomUUID();
        svgRenderTemplate.setId("TestSvgTemplate");
        String svgTemplate = """
                    <svg xmlns=\\"http://www.w3.org/2000/svg\\" width=\\"200\\" height=\\"200\\">
                    <rect width=\\"200\\" height=\\"200\\" fill=\\"#ff6347\\"/>
                    <text x=\\"100\\" y=\\"100\\" font-size=\\"30\\" text-anchor=\\"middle\\" fill=\\"white\\">
                    Hello, SVG!
                    </text></svg>
                """;
        svgRenderTemplate.setSvgTemplate(svgTemplate);
        svgRenderTemplate.setLastModified(LocalDateTime.now());
        Optional<SvgRenderTemplate> optional = Optional.of(svgRenderTemplate);
        Mockito.when(svgRenderTemplateRepository.findById(Mockito.any())).thenReturn(optional);
        SvgRenderTemplateDto svgRenderTemplateResponse = svgRenderTemplateService.getSvgTemplate("TestSvgTemplate");
        Assert.assertNotNull(svgRenderTemplateResponse);
        Assert.assertEquals(svgRenderTemplate.getId(), svgRenderTemplateResponse.getId());
        Assert.assertEquals(svgTemplate, optional.get().getSvgTemplate());
    }

    @Test
    public void getSvgTemplate_withInvalidId_thenFail() {
        Mockito.when(svgRenderTemplateRepository.findById(Mockito.any())).thenReturn(Optional.empty());
        CertifyException certifyException = Assert.assertThrows(CertifyException.class, () -> {
            svgRenderTemplateService.getSvgTemplate("RandomSvgTemplate");
        });
        Assert.assertEquals(ErrorConstants.INVALID_TEMPLATE_ID, certifyException.getErrorCode());
    }

}
