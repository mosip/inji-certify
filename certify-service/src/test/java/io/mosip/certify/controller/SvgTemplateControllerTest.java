package io.mosip.certify.controller;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.entity.SvgTemplate;
import io.mosip.certify.core.exception.TemplateException;
import io.mosip.certify.core.spi.SvgTemplateService;
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

import java.net.http.HttpHeaders;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

@RunWith(SpringRunner.class)
@WebMvcTest(value=SvgTemplateController.class)
public class SvgTemplateControllerTest {
    @Autowired
    MockMvc mockMvc;

    @MockBean
    SvgTemplateService svgTemplateService;

    @MockBean
    ParsedAccessToken parsedAccessToken;

    @Test
    public void  getSvgTemplate_withValidId_thenPass() throws Exception {
        SvgTemplate svgTemplate = new SvgTemplate();
        UUID id = UUID.randomUUID();
        svgTemplate.setId(id);
        String template = """
                    <svg xmlns=\\"http://www.w3.org/2000/svg\\" width=\\"200\\" height=\\"200\\">
                    <rect width=\\"200\\" height=\\"200\\" fill=\\"#ff6347\\"/>
                    <text x=\\"100\\" y=\\"100\\" font-size=\\"30\\" text-anchor=\\"middle\\" fill=\\"white\\">
                    Hello, SVG!
                    </text></svg>
                """;
        svgTemplate.setTemplate(template);
        LocalDateTime date = LocalDateTime.now();
        svgTemplate.setCreatedtimes(date);
        svgTemplate.setUpdatedtimes(date);

        Mockito.when(svgTemplateService.getSvgTemplate(Mockito.any())).thenReturn(svgTemplate);

        mockMvc.perform(get("/public/svg-template/" + id))
                .andExpect(status().isOk())
                .andExpect(content().string(svgTemplate.getTemplate()))
                .andExpect(content().contentType("image/svg+xml"))
                .andExpect(header().string("Cache-Control", "max-age=86400, public"));
    }

    @Test
    public void  getSvgTemplate_withInValidId_thenFail() throws Exception {
        TemplateException templateException = new TemplateException(ErrorConstants.INVALID_TEMPLATE_ID);
        UUID id = UUID.randomUUID();
        Mockito.when(svgTemplateService.getSvgTemplate(id)).thenThrow(templateException);

        mockMvc.perform(get("/public/svg-template/" + id))
                .andExpect(status().isNotFound());
    }
}
