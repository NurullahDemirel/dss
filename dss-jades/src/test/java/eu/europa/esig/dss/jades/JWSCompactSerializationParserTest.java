package eu.europa.esig.dss.jades;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertTimeout;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JWSCompactSerializationParserTest {

    // See DSS-3938
    @Test
    void performanceTest() {
        DSSDocument document = new FileDocument("src/test/resources/validation/jades-level-b-full-type.json");
        JWSCompactSerializationParser parser = new JWSCompactSerializationParser(document);
        assertTrue(parser.isSupported());

        assertTimeout(Duration.ofMillis(500), () -> {
            for (int i = 0; i < 100; i++) {
                assertTrue(parser.isSupported());
            }
        });
    }

}
