package lk.gov.dmt.certify.plugin.transport;

import java.io.ByteArrayOutputStream;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;

import static lk.gov.dmt.certify.plugin.error.DmtExchangeErrors.*;

/** Rejects oversized responses while they are streamed. */
final class LimitedBodySubscriber implements HttpResponse.BodySubscriber<byte[]> {
    private final int limit;
    private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    private final CompletableFuture<byte[]> body = new CompletableFuture<>();
    private Flow.Subscription subscription;

    LimitedBodySubscriber(int limit) { this.limit = limit; }
    @Override
    public CompletionStage<byte[]> getBody() { return body; }
    @Override
    public void onSubscribe(Flow.Subscription subscription) {
        this.subscription = subscription;
        subscription.request(1);
    }
    @Override
    public void onNext(List<ByteBuffer> buffers) {
        for (ByteBuffer buffer : buffers) {
            if (buffer.remaining() > limit - bytes.size()) {
                body.completeExceptionally(error(Failure.RESPONSE_TOO_LARGE));
                subscription.cancel();
                return;
            }
            byte[] chunk = new byte[buffer.remaining()];
            buffer.get(chunk);
            bytes.writeBytes(chunk);
        }
        subscription.request(1);
    }
    @Override
    public void onError(Throwable error) { body.completeExceptionally(error); }
    @Override
    public void onComplete() { body.complete(bytes.toByteArray()); }
}
