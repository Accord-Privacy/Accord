import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { AccordApi } from '../api';

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

describe('AccordApi', () => {
  let api: AccordApi;

  beforeEach(() => {
    mockFetch.mockReset();
    api = new AccordApi('https://test.accord.local');
  });

  describe('URL construction', () => {
    it('strips trailing slashes from base URL', () => {
      const a = new AccordApi('https://example.com///');
      expect(a.getBaseUrl()).toBe('https://example.com');
    });

    it('builds correct endpoint URLs', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ status: 'healthy' }),
      });

      await api.health();

      expect(mockFetch).toHaveBeenCalledWith(
        'https://test.accord.local/health',
        expect.objectContaining({ headers: expect.any(Object) }),
      );
    });

    it('includes query params for paginated requests', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ messages: [], has_more: false }),
      });

      api.setToken('tok-123');
      await api.getChannelMessages('ch-1', '', 25, 'before-id');

      const url = mockFetch.mock.calls[0][0] as string;
      expect(url).toContain('/channels/ch-1/messages');
      expect(url).toContain('limit=25');
      expect(url).toContain('before=before-id');
    });
  });

  describe('auth header attachment', () => {
    it('does not attach Authorization header when no token set', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ status: 'healthy' }),
      });

      await api.health();

      const headers = mockFetch.mock.calls[0][1].headers;
      expect(headers.Authorization).toBeUndefined();
    });

    it('attaches Bearer token when set', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ status: 'healthy' }),
      });

      api.setToken('my-secret-token');
      await api.health();

      const headers = mockFetch.mock.calls[0][1].headers;
      expect(headers.Authorization).toBe('Bearer my-secret-token');
    });

    it('updates header when token changes', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ status: 'healthy' }),
      });

      api.setToken('token-1');
      await api.health();
      expect(mockFetch.mock.calls[0][1].headers.Authorization).toBe('Bearer token-1');

      api.setToken('token-2');
      await api.health();
      expect(mockFetch.mock.calls[1][1].headers.Authorization).toBe('Bearer token-2');
    });
  });

  describe('error response parsing', () => {
    it('throws on 429 rate limit', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 429,
        json: async () => ({ error: 'Rate limit exceeded' }),
      });

      await expect(api.health()).rejects.toThrow('Rate limit exceeded');
    });

    it('throws on 401 unauthorized (no refresher)', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 401,
        json: async () => ({ error: 'Invalid token' }),
      });

      await expect(api.health()).rejects.toThrow('Invalid token');
    });

    it('throws on 500 server error', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        json: async () => ({ error: 'Internal server error' }),
      });

      await expect(api.health()).rejects.toThrow('Internal server error');
    });

    it('falls back to HTTP status when no error field', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 503,
        json: async () => ({}),
      });

      await expect(api.health()).rejects.toThrow('HTTP 503');
    });

    it('retries on 401 when token refresher is set', async () => {
      let callCount = 0;
      mockFetch.mockImplementation(async () => {
        callCount++;
        if (callCount === 1) {
          return { ok: false, status: 401, json: async () => ({ error: 'Expired' }) };
        }
        return { ok: true, status: 200, json: async () => ({ status: 'healthy' }) };
      });

      api.setToken('old-token');
      api.setTokenRefresher(async () => {
        api.setToken('new-token');
        return 'new-token';
      });

      const result = await api.health();
      expect(result).toEqual({ status: 'healthy' });
      expect(callCount).toBe(2);
    });
  });
});
