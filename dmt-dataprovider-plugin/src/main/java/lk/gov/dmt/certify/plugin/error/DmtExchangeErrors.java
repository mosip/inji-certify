package lk.gov.dmt.certify.plugin.error;

import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.api.util.ErrorConstants;

public final class DmtExchangeErrors {
    private DmtExchangeErrors() {}

    public enum Failure {
        INVALID_IDENTITY, INVALID_LOOKUP, UNSUPPORTED_ROUTE, IDENTITY_ISSUER_MISMATCH, NOT_FOUND,
        UPSTREAM_AUTHENTICATION, UPSTREAM_STATUS, TIMEOUT, TRANSPORT,
        RESPONSE_TOO_LARGE, INVALID_RESPONSE, INTERRUPTED
    }

    public static ExchangeFailure error(Failure failure) {
        return error(failure, null);
    }

    public static ExchangeFailure error(Failure failure, Throwable cause) {
        ExchangeFailure exception = new ExchangeFailure(failure);
        if (cause != null) exception.initCause(cause);
        return exception;
    }

    public static final class ExchangeFailure extends DataProviderExchangeException {
        private final Failure failure;

        private ExchangeFailure(Failure failure) {
            super(ErrorConstants.VCI_DATAFETCH_FAILED, "DMT data fetch failed: " + failure.name());
            this.failure = failure;
        }

        public Failure failure() { return failure; }
    }
}
