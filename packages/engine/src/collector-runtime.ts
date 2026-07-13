export interface CollectorRuntimeOptions {
  timeoutMs?: number;
  maxAttempts?: number;
  initialBackoffMs?: number;
  maxBackoffMs?: number;
  sleep?: (milliseconds: number) => Promise<void>;
}

export interface CollectorRuntimeResult<T> {
  value: T;
  attempts: number;
}

const RETRYABLE =
  /(throttl|rate.?exceed|too many requests|timeout|timed out|temporar|unavailable|503|429)/i;

export function isRetryableCollectorError(error: unknown): boolean {
  return RETRYABLE.test(error instanceof Error ? error.message : String(error));
}

/** Execute an external collector operation with bounded retries and a deadline. */
export async function runCollector<T>(
  operation: (signal: AbortSignal) => Promise<T>,
  options: CollectorRuntimeOptions = {},
): Promise<CollectorRuntimeResult<T>> {
  const timeoutMs = options.timeoutMs ?? 120_000;
  const maxAttempts = Math.max(1, options.maxAttempts ?? 3);
  const initialBackoffMs = options.initialBackoffMs ?? 250;
  const maxBackoffMs = options.maxBackoffMs ?? 5_000;
  const sleep =
    options.sleep ??
    ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
  let lastError: unknown;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const value = await operation(controller.signal);
      return { value, attempts: attempt };
    } catch (error) {
      lastError =
        error instanceof Error && controller.signal.aborted
          ? new Error(`collector timed out after ${timeoutMs}ms`, { cause: error })
          : error;
      if (attempt >= maxAttempts || !isRetryableCollectorError(lastError)) throw lastError;
      const delay = Math.min(maxBackoffMs, initialBackoffMs * 2 ** (attempt - 1));
      await sleep(delay);
    } finally {
      clearTimeout(timer);
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

/** Execute a collection batch without exceeding the provider-safe concurrency limit. */
export async function runCollectorBatch<T>(
  operations: Array<(signal: AbortSignal) => Promise<T>>,
  options: CollectorRuntimeOptions & { maxConcurrency?: number } = {},
): Promise<Array<CollectorRuntimeResult<T>>> {
  const results = new Array<CollectorRuntimeResult<T>>(operations.length);
  const maxConcurrency = Math.max(1, Math.min(options.maxConcurrency ?? 4, operations.length || 1));
  let next = 0;
  const worker = async () => {
    while (next < operations.length) {
      const index = next;
      next += 1;
      results[index] = await runCollector(operations[index]!, options);
    }
  };
  await Promise.all(Array.from({ length: maxConcurrency }, worker));
  return results;
}
