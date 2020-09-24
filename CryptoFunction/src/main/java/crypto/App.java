package crypto;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.cloudwatchlogs.emf.logger.MetricsLogger;
import software.amazon.cloudwatchlogs.emf.model.Unit;
import software.amazon.lambda.powertools.logging.PowertoolsLogging;
import software.amazon.lambda.powertools.metrics.PowertoolsMetrics;
import software.amazon.lambda.powertools.metrics.PowertoolsMetricsLogger;
import software.amazon.lambda.powertools.tracing.PowerTracer;
import software.amazon.lambda.powertools.tracing.PowertoolsTracing;

import static software.amazon.lambda.powertools.metrics.PowertoolsMetricsLogger.withSingleMetric;

/**
 * Handler for requests to Lambda function.
 */
public class App implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    Logger log = LogManager.getLogger();

    MetricsLogger metricsLogger = PowertoolsMetricsLogger.metricsLogger();

    private static AwsCrypto CRYPTO;
    private static KmsMasterKeyProvider MASTER_KEY_PROVIDER;
    private static Map<String, String> ENCRYPTION_CONTEXT;

    private static final String EXAMPLE_DATA = "Hello World!";

    static {
        CRYPTO = new AwsCrypto();
        MASTER_KEY_PROVIDER = KmsMasterKeyProvider.builder().withKeysForEncryption(System.getenv("MASTER_KEY_ARN")).build();
        ENCRYPTION_CONTEXT = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");
    }

    @PowertoolsLogging(logEvent = true)
    @PowertoolsTracing()
    @PowertoolsMetrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(final APIGatewayProxyRequestEvent input, final Context context) {
        // to test, we encrypt and then decrypt the same text
        byte[] ciphertext = encryptData(EXAMPLE_DATA);
        String result = decryptData(ciphertext);

        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("X-Custom-Header", "application/json");

        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent()
                .withHeaders(headers);
        String output = String.format("{ \"result\": \"%s\" }", result);

        return response
                .withStatusCode(200)
                .withBody(output);
    }

    @PowertoolsTracing(captureResponse = false)
    private byte[] encryptData(String data) {
        byte[] bdata = data.getBytes(StandardCharsets.UTF_8);

        Instant start = Instant.now(); // elapsed time
        final CryptoResult<byte[], KmsMasterKey> encryptResult = CRYPTO.encryptData(MASTER_KEY_PROVIDER, bdata, ENCRYPTION_CONTEXT);
        final byte[] ciphertext = encryptResult.getResult();
        Instant finish = Instant.now(); // elapsed time
        long elapsedTime = Duration.between(start, finish).toMillis();
        metricsLogger.putMetric("encryptDuration", elapsedTime, Unit.MILLISECONDS);

        log.info(ciphertext);
        return ciphertext;
    }

    @PowertoolsTracing()
    private String decryptData(byte[] ciphertext) {
        Instant start = Instant.now(); // elapsed time
        final CryptoResult<byte[], KmsMasterKey> decryptResult = CRYPTO.decryptData(MASTER_KEY_PROVIDER, ciphertext);
        Instant finish = Instant.now(); // elapsed time
        long elapsedTime = Duration.between(start, finish).toMillis();
        metricsLogger.putMetric("decryptDuration", elapsedTime, Unit.MILLISECONDS);

        if (!decryptResult.getMasterKeyIds().get(0).equals(System.getenv("MASTER_KEY_ARN"))) {
            PowerTracer.putAnnotation("error", "WrongKMSKey");
            throw new IllegalStateException("Wrong KMS Key");
        }

        if (!ENCRYPTION_CONTEXT.entrySet().stream().allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
            PowerTracer.putAnnotation("error", "WrongEncryptionContext");
            throw new IllegalStateException("Wrong encryption context");
        }

        return new String(decryptResult.getResult(), StandardCharsets.UTF_8);
    }
}
