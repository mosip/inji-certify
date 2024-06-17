package io.inji.certify;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class CertifyApplicationTests {

    @Test
    public void test() {
        CertifyServiceApplication.main(new String[] {});
        Assertions.assertNotNull(CertifyServiceApplication.class);
    }

}