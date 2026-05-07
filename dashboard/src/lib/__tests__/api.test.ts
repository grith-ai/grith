import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as api from '../api';

describe('API Client', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('getHealth fetches /api/health', async () => {
    const mockResponse = { status: 'healthy', uptime_secs: 100, version: '0.1.0' };
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockResponse),
    });

    const result = await api.getHealth();
    expect(result).toEqual(mockResponse);
    expect(fetch).toHaveBeenCalledWith(expect.stringContaining('/api/health'), expect.any(Object));
  });

  it('getDigestItems fetches /api/digest', async () => {
    const mockResponse: unknown[] = [];
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockResponse),
    });

    const result = await api.getDigestItems();
    expect(result).toEqual([]);
  });

  it('throws on non-ok response', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
      text: () => Promise.resolve('Server error'),
    });

    await expect(api.getHealth()).rejects.toThrow();
  });

  it('approveDigest sends POST', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ success: true }),
    });

    await api.approveDigest('test-id');
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/digest/test-id/approve'),
      expect.objectContaining({ method: 'POST' }),
    );
  });
});
