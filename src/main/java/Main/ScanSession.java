package Main;

/** A dashboard run owns its counters and all queued/completed callbacks. */
final class ScanSession {
    volatile boolean cancelled;
    private int total, finished, errors, active;

    synchronized void planned(int n) { if (!cancelled) total += n; }
    synchronized void started() { if (!cancelled) active++; }
    synchronized void ended() { if (!cancelled) active = Math.max(0, active - 1); }
    synchronized void finished(int n) { if (!cancelled) finished += n; }
    synchronized void failed(int n) { if (!cancelled) errors += n; }
    synchronized void cancel() { cancelled = true; active = 0; }
    synchronized int[] counts() {
        return new int[]{total, finished, errors, cancelled ? Math.max(0, total - finished - errors) : 0, active};
    }
}
