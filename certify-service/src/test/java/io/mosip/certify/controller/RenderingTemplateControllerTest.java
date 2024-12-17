package io.mosip.certify.controller;

import io.mosip.certify.api.dto.RenderingTemplateDTO;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.services.entity.RenderingTemplate;
import io.mosip.certify.core.exception.RenderingTemplateException;
import io.mosip.certify.services.spi.RenderingTemplateService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.time.LocalDateTime;

@RunWith(SpringRunner.class)
@WebMvcTest(value= RenderingTemplateController.class)
public class RenderingTemplateControllerTest {
    @Autowired
    MockMvc mockMvc;

    @MockBean
    RenderingTemplateService renderingTemplateService;

    @MockBean
    ParsedAccessToken parsedAccessToken;

    @Test
    public void  getSvgTemplate_withValidId_thenPass() throws Exception {
        RenderingTemplateDTO renderingTemplateDTO = new RenderingTemplateDTO();
        renderingTemplateDTO.setId("fake-id");
        String template = """
                    <svg xmlns=\\"http://www.w3.org/2000/svg\\" width=\\"200\\" height=\\"200\\">
                    <rect width=\\"200\\" height=\\"200\\" fill=\\"#ff6347\\"/>
                    <text x=\\"100\\" y=\\"100\\" font-size=\\"30\\" text-anchor=\\"middle\\" fill=\\"white\\">
                    Hello, SVG!
                    </text></svg>
                """;
        renderingTemplateDTO.setTemplate(template);
        LocalDateTime date = LocalDateTime.now();
        renderingTemplateDTO.setCreatedTimes(date);
        renderingTemplateDTO.setUpdatedTimes(date);

        Mockito.when(renderingTemplateService.getSvgTemplate(Mockito.any())).thenReturn(renderingTemplateDTO);

        mockMvc.perform(get("/public/rendering-template/fake-id"))
                .andExpect(status().isOk())
                .andExpect(content().string(renderingTemplateDTO.getTemplate()))
                .andExpect(content().contentType("image/svg+xml"))
                .andExpect(header().string("Cache-Control", "max-age=86400, public"));
    }

    @Test
    public void  getSvgTemplate_withInValidId_thenFail() throws Exception {
        RenderingTemplateException templateException = new RenderingTemplateException(ErrorConstants.INVALID_TEMPLATE_ID);
        Mockito.when(renderingTemplateService.getSvgTemplate("fake-id")).thenThrow(templateException);

        mockMvc.perform(get("/public/rendering-template/fake-id"))
                .andExpect(status().isNotFound());
    }
}
