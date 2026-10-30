package Main;

import org.junit.After;
import org.junit.Test;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;

public class ScanQueueTest {
    @After public void cleanup() { Utils.shutdownSharedExecutor(); }

    @Test public void saturatedQueueCannotRunNetworkWorkOnTheSubmittingThread() throws Exception {
        ExecutorService pool = Utils.getSharedExecutor(2);
        ScanSession session = new ScanSession();
        CountDownLatch firstTwo = new CountDownLatch(2), release = new CountDownLatch(1), finished = new CountDownLatch(103);
        AtomicInteger active = new AtomicInteger(), peak = new AtomicInteger();
        Runnable task = () -> {
            int current = active.incrementAndGet(); peak.accumulateAndGet(current, Math::max); firstTwo.countDown();
            try { release.await(4, TimeUnit.SECONDS); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            finally { active.decrementAndGet(); finished.countDown(); }
        };
        for (int i = 0; i < 2; i++) Utils.submitScan(pool, session, task);
        assertTrue(firstTwo.await(2, TimeUnit.SECONDS));
        for (int i = 0; i < 100; i++) Utils.submitScan(pool, session, task);
        Thread producer = new Thread(() -> Utils.submitScan(pool, session, task));
        try {
            producer.start();
            producer.join(100);
            assertTrue("Producer should wait for queue capacity", producer.isAlive());
            assertEquals(2, peak.get());
            assertSame("Resizing must not create an overlapping pool", pool, Utils.getSharedExecutor(1));
            assertEquals(2, ((ThreadPoolExecutor) pool).getMaximumPoolSize());
            release.countDown();
            assertTrue(finished.await(3, TimeUnit.SECONDS));
            producer.join(2000); assertFalse(producer.isAlive());
            assertEquals(2, peak.get());
        } finally { release.countDown(); producer.join(2000); }
    }

    @Test public void cancelledQueuedTasksNeverExecuteAfterRunningTaskFinishes() throws Exception {
        ExecutorService pool = Utils.getSharedExecutor(1);
        ScanSession session = new ScanSession();
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1), drained = new CountDownLatch(1);
        AtomicInteger sends = new AtomicInteger();
        Utils.submitScan(pool, session, () -> {
            sends.incrementAndGet(); entered.countDown();
            try { release.await(3, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
        });
        assertTrue(entered.await(2, TimeUnit.SECONDS));
        for (int i = 0; i < 10; i++) Utils.submitScan(pool, session, sends::incrementAndGet);
        session.cancel(); release.countDown();
        pool.execute(drained::countDown);
        assertTrue(drained.await(3, TimeUnit.SECONDS));
        assertEquals(1, sends.get());
    }

    @Test public void loweringConcurrencyWhenIdleReusesTheSamePool() {
        ThreadPoolExecutor first = (ThreadPoolExecutor) Utils.getSharedExecutor(5);
        assertSame(first, Utils.getSharedExecutor(1));
        assertEquals(1, first.getCorePoolSize()); assertEquals(1, first.getMaximumPoolSize());
        assertSame(first, Utils.getSharedExecutor(3));
        assertEquals(3, first.getMaximumPoolSize());
    }

    @Test public void preparationQueueReportsOverloadInsteadOfCreatingUnboundedThreads() throws Exception {
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        try {
            assertTrue(Utils.dispatchScan(() -> {
                entered.countDown();
                try { release.await(3, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
            }));
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            for (int i = 0; i < 100; i++) assertTrue(Utils.dispatchScan(() -> {}));
            assertFalse(Utils.dispatchScan(() -> {}));
        } finally { release.countDown(); }
    }
}
