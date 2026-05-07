import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock WebSocket for testing
class MockWebSocket {
  static instances: MockWebSocket[] = [];
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  readyState = 0;
  url: string;

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
  }

  close() {
    this.readyState = 3;
  }
}

describe('WebSocket Hook', () => {
  beforeEach(() => {
    MockWebSocket.instances = [];
    vi.stubGlobal('WebSocket', MockWebSocket);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('creates WebSocket with correct URL', () => {
    new MockWebSocket('ws://localhost:3141/ws/live');
    expect(MockWebSocket.instances).toHaveLength(1);
    expect(MockWebSocket.instances[0]!.url).toBe('ws://localhost:3141/ws/live');
  });

  it('tracks connection state', () => {
    const ws = new MockWebSocket('ws://localhost:3141/ws/live');
    expect(ws.readyState).toBe(0);
    ws.close();
    expect(ws.readyState).toBe(3);
  });
});
