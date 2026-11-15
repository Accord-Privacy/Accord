/**
 * Errors of the relay's REST API.
 *
 * Routes changed for relay admission (SPEC-01 §6.2, the batch error
 * conventions of §6.3) answer `{error, code, reason, retry_after?}`: `error`
 * and `code` keep their old meaning, `reason` is machine-readable. Older relays
 * and other routes send only `{error, code}`, so `reason` may be absent.
 *
 * This module has no runtime dependencies, so components can classify errors
 * even where tests replace the `api` module with a mock.
 */
export class ApiError extends Error {
  /** HTTP status of the answer. */
  readonly status: number;
  /** Machine-readable reason (SPEC-01 §6.4), when the relay sent one. */
  readonly reason?: string;
  /** Seconds to wait before retrying, sent with `rate_limited`. */
  readonly retryAfter?: number;

  constructor(message: string, status: number, reason?: string, retryAfter?: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.reason = reason;
    this.retryAfter = retryAfter;
  }
}

/** Build an {@link ApiError} from an error answer and its parsed body. */
export function apiErrorFromBody(status: number, body: unknown): ApiError {
  const b = (body && typeof body === 'object' ? body : {}) as Record<string, unknown>;
  const message = typeof b.error === 'string' && b.error ? b.error : `HTTP ${status}`;
  const reason = typeof b.reason === 'string' ? b.reason : undefined;
  const retryAfter =
    typeof b.retry_after === 'number' && Number.isFinite(b.retry_after) ? b.retry_after : undefined;
  return new ApiError(message, status, reason, retryAfter);
}

/** The `reason` of an API error (or of a WS failure frame), if any. */
export function errorReason(err: unknown): string | undefined {
  const reason = (err as { reason?: unknown } | null | undefined)?.reason;
  return typeof reason === 'string' ? reason : undefined;
}

/** The `retry_after` seconds of an API error or WS failure frame, if any. */
export function errorRetryAfter(err: unknown): number | undefined {
  const e = err as { retryAfter?: unknown; retry_after?: unknown } | null | undefined;
  const value = e?.retryAfter ?? e?.retry_after;
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

/** The HTTP status of an API error, if it is one. */
export function errorStatus(err: unknown): number | undefined {
  const status = (err as { status?: unknown } | null | undefined)?.status;
  return typeof status === 'number' ? status : undefined;
}

/** The human-readable text of any error. */
export function errorText(err: unknown, fallback: string): string {
  if (err instanceof Error && err.message) return err.message;
  const text = (err as { error?: unknown } | null | undefined)?.error;
  return typeof text === 'string' && text ? text : fallback;
}
