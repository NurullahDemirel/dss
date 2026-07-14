package eu.europa.esig.dss.lote.runnable;

import eu.europa.esig.dss.lote.cache.access.LoTECacheAccessByKey;
import eu.europa.esig.dss.lote.source.LoTESource;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.client.http.MemoryDataLoader;
import eu.europa.esig.dss.validation.job.cache.CacheKey;
import eu.europa.esig.dss.validation.job.cache.DownloadCache;
import eu.europa.esig.dss.validation.job.cache.ParsingCache;
import eu.europa.esig.dss.validation.job.cache.ValidationCache;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class LoTEAnalysisNoExecutorTest {

    private static final Logger LOG = LoggerFactory.getLogger(LoTEAnalysisErrorTest.class);

    @Test
    void test() throws Exception {
        ExecutorService executorService = Executors.newFixedThreadPool(1);
        CountDownLatch latch = new CountDownLatch(1);

        LoTESource loteSource = new LoTESource();
        loteSource.setUrl("LU");

        Map<String, byte[]> memoryMap = new HashMap<>();
        memoryMap.put("LU", new byte[] { '0' });

        LoTEAnalysis process = new LoTEAnalysis(loteSource, new LoTECacheAccessByKey(
                new CacheKey("LU"), new DownloadCache(), new ParsingCache(), new ValidationCache()),
                new FileCacheDataLoader(new MemoryDataLoader(memoryMap)), latch);
        assertNotNull(process);

        executorService.submit(process);

        try {
            latch.await(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        assertEquals(0, latch.getCount());

        shutdownNowAndAwaitTermination(executorService);
    }

    protected void shutdownNowAndAwaitTermination(ExecutorService executorService) {
        executorService.shutdownNow();
        try {
            if (!executorService.awaitTermination(10, TimeUnit.SECONDS)) {
                LOG.warn("More than 10s to terminate the service executor");
            }
        } catch (InterruptedException e) {
            LOG.warn("Unable to interrupt the service executor", e);
            Thread.currentThread().interrupt();
        }
    }

}
