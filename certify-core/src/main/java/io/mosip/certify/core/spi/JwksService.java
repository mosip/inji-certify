package io.mosip.certify.core.spi;

import org.springframework.http.ResponseEntity;
import java.util.Map;

public interface JwksService {
    Map<String, Object> getJwks();
}

