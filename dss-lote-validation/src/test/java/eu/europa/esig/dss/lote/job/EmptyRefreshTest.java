package eu.europa.esig.dss.lote.job;

import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EmptyRefreshTest {

    @Test
    void test() {
        LoTEValidationJob job = new LoTEValidationJob();
        NullPointerException exception = assertThrows(NullPointerException.class, job::offlineRefresh);
        assertEquals("The offlineLoader must be defined!", exception.getMessage());

        job.setOfflineDataLoader(new FileCacheDataLoader());
        job.setDebug(true);

        job.offlineRefresh();

        exception = assertThrows(NullPointerException.class, job::onlineRefresh);
        assertEquals("The onlineLoader must be defined!", exception.getMessage());

        job.setOnlineDataLoader(new FileCacheDataLoader());
        job.onlineRefresh();
    }

}
