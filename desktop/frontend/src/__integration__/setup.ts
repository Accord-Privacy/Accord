/**
 * The two-client tests run in Vitest's `node` environment, where fetch,
 * WebSocket, Blob and WebCrypto are Node's own, so traffic really crosses the
 * network to the relay. Node has no XMLHttpRequest, which `api.uploadAttachment`
 * uses (for upload progress in the webview); this shim implements the part it
 * needs on top of fetch, sending the Blob body unchanged.
 */

type Listener = (event: { lengthComputable?: boolean; loaded?: number; total?: number }) => void;

class FetchXMLHttpRequest {
  status = 0;
  responseText = '';
  timeout = 0;
  private method = 'GET';
  private url = '';
  private headers: Record<string, string> = {};
  private responseHeaders: Headers | null = null;
  private listeners = new Map<string, Listener[]>();
  private uploadListeners = new Map<string, Listener[]>();
  readonly upload = {
    addEventListener: (type: string, l: Listener) => {
      this.uploadListeners.set(type, [...(this.uploadListeners.get(type) ?? []), l]);
    },
  };

  addEventListener(type: string, l: Listener): void {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), l]);
  }

  open(method: string, url: string): void {
    this.method = method;
    this.url = url;
  }

  setRequestHeader(name: string, value: string): void {
    this.headers[name] = value;
  }

  getResponseHeader(name: string): string | null {
    return this.responseHeaders?.get(name) ?? null;
  }

  private fire(map: Map<string, Listener[]>, type: string, event: Parameters<Listener>[0] = {}): void {
    for (const l of map.get(type) ?? []) l(event);
  }

  send(body?: Blob | null): void {
    const total = body?.size ?? 0;
    void fetch(this.url, { method: this.method, headers: this.headers, body: body ?? undefined })
      .then(async response => {
        this.fire(this.uploadListeners, 'progress', { lengthComputable: true, loaded: total, total });
        this.status = response.status;
        this.responseHeaders = response.headers;
        this.responseText = await response.text();
        this.fire(this.listeners, 'load');
      })
      .catch(() => this.fire(this.listeners, 'error'));
  }
}

if (typeof (globalThis as { XMLHttpRequest?: unknown }).XMLHttpRequest === 'undefined') {
  (globalThis as { XMLHttpRequest?: unknown }).XMLHttpRequest = FetchXMLHttpRequest;
}

/** An in-memory `localStorage` (the E2EE session manager persists sessions there). */
class MemoryStorage {
  private map = new Map<string, string>();
  get length(): number {
    return this.map.size;
  }
  key(i: number): string | null {
    return [...this.map.keys()][i] ?? null;
  }
  getItem(k: string): string | null {
    return this.map.get(k) ?? null;
  }
  setItem(k: string, v: string): void {
    this.map.set(k, String(v));
  }
  removeItem(k: string): void {
    this.map.delete(k);
  }
  clear(): void {
    this.map.clear();
  }
}

if (typeof (globalThis as { localStorage?: unknown }).localStorage === 'undefined') {
  (globalThis as { localStorage?: unknown }).localStorage = new MemoryStorage();
}
