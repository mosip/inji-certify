package lk.gov.dmt.certify.plugin.credential.erl;

import lk.gov.dmt.certify.plugin.config.DmtProviderProperties;
import lk.gov.dmt.certify.plugin.model.VcData;
import lk.gov.dmt.certify.plugin.model.VcFetchRequest;
import lk.gov.dmt.certify.plugin.spi.DmtDataClient;
import lk.gov.dmt.certify.plugin.spi.VcDataFetcher;
import lk.gov.dmt.certify.plugin.validation.EndpointTemplates;
import lk.gov.dmt.certify.plugin.validation.TextValidation;

import io.mosip.certify.api.exception.DataProviderExchangeException;

import java.util.Map;
import java.util.Set;

import static lk.gov.dmt.certify.plugin.error.DmtExchangeErrors.*;

public final class ErlDataFetcher implements VcDataFetcher {
    private final DmtDataClient apiClient;

    public ErlDataFetcher(DmtDataClient apiClient) {
        this.apiClient = apiClient;
    }

    @Override
    public String strategyId() { return "erl"; }

    @Override
    public void validateRoute(DmtProviderProperties.Route route) {
        TextValidation.require(EndpointTemplates.variables(route.endpointPath()).equals(Set.of("vehicleNo")),
                "ERL endpoint requires the vehicleNo path variable");
    }

    @Override
    public VcData fetch(VcFetchRequest request, DmtProviderProperties.Route route) throws DataProviderExchangeException {
        String vehicleNo = request.lookupAttributes().get("vehicleNo");
        // Interim contract: canonical ASCII letters/digits separated by hyphens, without normalization.
        if (vehicleNo == null || vehicleNo.length() > 32 || !vehicleNo.matches("[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*")) {
            throw error(Failure.INVALID_LOOKUP);
        }
        ErlResponseDto response = ErlResponseDto.parse(apiClient.get(route, request, Map.of("vehicleNo", vehicleNo)));
        if (!vehicleNo.equals(response.vehicleNo())) throw error(Failure.INVALID_RESPONSE);
        return response.toVcData();
    }
}
