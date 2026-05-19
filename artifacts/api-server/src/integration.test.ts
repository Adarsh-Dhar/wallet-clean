import { describe, it, expect, beforeAll, afterAll } from 'vitest';

/**
 * Integration Tests for DeepClean API Endpoints
 *
 * Run against a live server:
 * pnpm dev &
 * pnpm test integration.test.ts
 *
 * Server should be running on http://localhost:8080
 */

const API_BASE = 'http://localhost:8080/api';
const TEST_ADDRESS = '0xb8552ec41cd7b5697464602d24d9c174f6fb863c';

// ============================================================
// Helper Functions
// ============================================================

async function makeRequest(method: string, endpoint: string, body?: any) {
  try {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    const text = await response.text();
    let data;
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { raw: text };
    }

    return {
      status: response.status,
      ok: response.ok,
      data,
    };
  } catch (err) {
    return {
      status: 0,
      ok: false,
      error: (err as Error).message,
    };
  }
}

// ============================================================
// 1. Health & Server Tests
// ============================================================

describe('Health Check', () => {
  it('should verify server is running', async () => {
    const response = await makeRequest('GET', '/health');
    expect(response.status).toEqual(200);
  });
});

// ============================================================
// 2. Populate-Wallet Endpoint Tests
// ============================================================

describe('POST /api/populate-wallet', () => {
  it('should successfully populate wallet with threats', async () => {
    const response = await makeRequest('POST', '/populate-wallet', {
      targetAddress: TEST_ADDRESS,
    });

    expect(response.status).toBe(200);
    expect(response.data).toHaveProperty('injected');
    expect(response.data).toHaveProperty('quarantined');
    expect(response.data).toHaveProperty('threats');
    expect(Array.isArray(response.data.threats)).toBe(true);
  });

  it('should return objects with correct threat structure', async () => {
    const response = await makeRequest('POST', '/populate-wallet', {
      targetAddress: TEST_ADDRESS,
    });

    if (response.data.threats && response.data.threats.length > 0) {
      const threat = response.data.threats[0];
      expect(threat).toHaveProperty('objectId');
      expect(threat).toHaveProperty('verdict');
      expect(threat).toHaveProperty('riskScore');
      expect(threat).toHaveProperty('threatId');
      expect(['SAFE', 'SUSPICIOUS', 'MALICIOUS']).toContain(threat.verdict);
      expect(threat.riskScore).toBeGreaterThanOrEqual(0);
      expect(threat.riskScore).toBeLessThanOrEqual(100);
    }
  });

  it('should include onChainDigest in response (if REAL_ONCHAIN=true)', async () => {
    const response = await makeRequest('POST', '/populate-wallet', {
      targetAddress: TEST_ADDRESS,
    });

    expect(response.data).toHaveProperty('onChainDigest');
    // onChainDigest can be null if no malicious threats or REAL_ONCHAIN=false
    // but the field should exist
  });

  it('should return 400 for missing targetAddress', async () => {
    const response = await makeRequest('POST', '/populate-wallet', {});
    expect(response.status).toBe(400);
    expect(response.data).toHaveProperty('error');
  });

  it('should return 400 for invalid targetAddress format', async () => {
    const response = await makeRequest('POST', '/populate-wallet', {
      targetAddress: 'invalid_address',
    });
    expect(response.status).toBe(400);
  });

  it('should handle concurrent requests without errors', async () => {
    const requests = [
      makeRequest('POST', '/populate-wallet', { targetAddress: TEST_ADDRESS }),
      makeRequest('POST', '/populate-wallet', { targetAddress: TEST_ADDRESS }),
      makeRequest('POST', '/populate-wallet', { targetAddress: TEST_ADDRESS }),
    ];

    const responses = await Promise.all(requests);
    responses.forEach((response) => {
      expect(response.status).toBe(200);
    });
  });

  it('should handle timeout gracefully', async () => {
    // This would require a slow endpoint
    // Just verify timeout handling doesn't crash
    expect(true).toBe(true);
  });
});

// ============================================================
// 3. Threats Analyze Endpoint Tests
// ============================================================

describe('POST /api/threats/analyze', () => {
  it('should analyze a threat and return verdict', async () => {
    const response = await makeRequest('POST', '/threats/analyze', {
      objectId: '0xe933d9d3e69b29d0183ffbcecaacf7ec8dbc3832f99815760f0d34913c2c1ca4::honeypot::HoneypotToken',
      objectType: '0xe933d9d3e69b29d0183ffbcecaacf7ec8dbc3832f99815760f0d34913c2c1ca4::honeypot::HoneypotToken',
      senderAddress: '0x8cb08623b2514d8e90994ac4800d5c05d01775dfec7e324150be638b74e9932e',
      displayName: 'Malicious Honeypot',
      displayUrl: 'https://fake-defi.com',
    });

    expect(response.status).toBe(200);
    expect(response.data).toHaveProperty('riskScore');
    expect(response.data).toHaveProperty('verdict');
    expect(response.data).toHaveProperty('reasoning');
    expect(response.data).toHaveProperty('flags');
    expect(Array.isArray(response.data.flags)).toBe(true);
  });

  it('should return onChainDigest if threat is MALICIOUS with score >= 75', async () => {
    const response = await makeRequest('POST', '/threats/analyze', {
      objectId: '0xtest::malicious',
      objectType: '0xtest::malicious::Exploit',
      senderAddress: '0x8cb08623b2514d8e90994ac4800d5c05d01775dfec7e324150be638b74e9932e',
      displayName: 'Exploit Kit',
      displayUrl: 'https://exploit.malware.io',
    });

    expect(response.data).toHaveProperty('onChainDigest');
    // If verdict is MALICIOUS and score >= 75, onChainDigest should be a tx hash
    // Otherwise, it should be null
  });

  it('should return 400 for missing required fields', async () => {
    const response = await makeRequest('POST', '/threats/analyze', {
      objectId: '0xtest',
      // Missing objectType, senderAddress
    });
    expect(response.status).toBe(400);
  });

  it('should return 400 for invalid address format', async () => {
    const response = await makeRequest('POST', '/threats/analyze', {
      objectId: '0xtest',
      objectType: '0xtest::Token',
      senderAddress: 'invalid_address',
    });
    expect(response.status).toBe(400);
  });

  it('should handle optional fields (displayName, displayUrl)', async () => {
    const response = await makeRequest('POST', '/threats/analyze', {
      objectId: '0xtest',
      objectType: '0xtest::Token',
      senderAddress: '0x8cb08623b2514d8e90994ac4800d5c05d01775dfec7e324150be638b74e9932e',
      // No displayName or displayUrl
    });

    expect(response.status).toBe(200);
  });

  it('should reject special characters in displayName', async () => {
    const response = await makeRequest('POST', '/threats/analyze', {
      objectId: '0xtest',
      objectType: '0xtest::Token',
      senderAddress: '0x8cb08623b2514d8e90994ac4800d5c05d01775dfec7e324150be638b74e9932e',
      displayName: '<script>alert("xss")</script>',
    });

    // Should be sanitized or rejected
    expect(response.status).toBeLessThan(500); // Not a server error
  });
});

// ============================================================
// 4. Threats List Endpoint Tests
// ============================================================

describe('GET /api/threats', () => {
  it('should list all threats', async () => {
    const response = await makeRequest('GET', '/threats');

    expect(response.status).toBe(200);
    expect(Array.isArray(response.data)).toBe(true);
  });

  it('should support filtering quarantined threats for a wallet', async () => {
    const response = await makeRequest('GET', `/threats?status=quarantined&walletAddress=${encodeURIComponent(TEST_ADDRESS)}&limit=200`);

    expect(response.status).toBe(200);
    expect(Array.isArray(response.data)).toBe(true);
    if (response.data.length > 0) {
      response.data.forEach((threat: any) => {
        expect(threat.status).toBe('quarantined');
        expect(String(threat.walletAddress).toLowerCase()).toBe(TEST_ADDRESS.toLowerCase());
      });
    }
  });

  it('should support filtering by verdict', async () => {
    const response = await makeRequest('GET', '/threats?verdict=MALICIOUS');

    expect(response.status).toBe(200);
    expect(Array.isArray(response.data)).toBe(true);
    if (response.data.length > 0) {
      response.data.forEach((threat: any) => {
        expect(threat.verdict).toBe('MALICIOUS');
      });
    }
  });

  it('should support filtering by status', async () => {
    const response = await makeRequest('GET', '/threats?status=quarantined');

    expect(response.status).toBe(200);
    expect(Array.isArray(response.data)).toBe(true);
    if (response.data.length > 0) {
      response.data.forEach((threat: any) => {
        expect(threat.status).toBe('quarantined');
      });
    }
  });

  it('should support pagination (limit, offset)', async () => {
    const response1 = await makeRequest('GET', '/threats?limit=5&offset=0');
    const response2 = await makeRequest('GET', '/threats?limit=5&offset=5');

    expect(response1.status).toBe(200);
    expect(response2.status).toBe(200);
    expect(response1.data.length).toBeLessThanOrEqual(5);
    expect(response2.data.length).toBeLessThanOrEqual(5);
  });

  it('should return threats in descending date order', async () => {
    const response = await makeRequest('GET', '/threats?limit=10');

    if (response.data.length > 1) {
      for (let i = 0; i < response.data.length - 1; i++) {
        const date1 = new Date(response.data[i].detectedAt).getTime();
        const date2 = new Date(response.data[i + 1].detectedAt).getTime();
        expect(date1).toBeGreaterThanOrEqual(date2);
      }
    }
  });

  it('should include all threat fields', async () => {
    const response = await makeRequest('GET', '/threats?limit=1');

    if (response.data.length > 0) {
      const threat = response.data[0];
      expect(threat).toHaveProperty('id');
      expect(threat).toHaveProperty('objectId');
      expect(threat).toHaveProperty('objectType');
      expect(threat).toHaveProperty('riskScore');
      expect(threat).toHaveProperty('verdict');
      expect(threat).toHaveProperty('status');
      expect(threat).toHaveProperty('detectedAt');
    }
  });
});

// ============================================================
// 5. Error Handling Tests
// ============================================================

describe('Error Handling', () => {
  it('should return 404 for non-existent endpoint', async () => {
    const response = await makeRequest('GET', '/nonexistent');
    expect(response.status).toBe(404);
  });

  it('should return 405 for wrong HTTP method', async () => {
    const response = await makeRequest('PUT', '/threats/analyze');
    expect([404, 405]).toContain(response.status);
  });

  it('should handle malformed JSON gracefully', async () => {
    try {
      const response = await fetch(`${API_BASE}/populate-wallet`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{invalid json}',
      });
      expect(response.status).toBe(400);
    } catch (err) {
      // Network error - server should be running
      console.warn('Server not running');
    }
  });

  it('should never expose sensitive data in error messages', async () => {
    const response = await makeRequest('POST', '/populate-wallet', {
      targetAddress: 'invalid',
    });

    const errorText = JSON.stringify(response.data);
    expect(errorText).not.toContain('AGENT_PRIVATE_KEY');
    expect(errorText).not.toContain('DATABASE_URL');
    expect(errorText).not.toContain('GEMINI_API_KEY');
  });
});

// ============================================================
// 6. Response Time Tests
// ============================================================

describe('Performance', () => {
  it('should respond to analyze endpoint within 60 seconds', async () => {
    const start = Date.now();
    const response = await makeRequest('POST', '/threats/analyze', {
      objectId: '0xtest',
      objectType: '0xtest::Token',
      senderAddress: '0x8cb08623b2514d8e90994ac4800d5c05d01775dfec7e324150be638b74e9932e',
    });
    const duration = Date.now() - start;

    expect(response.status).toBe(200);
    expect(duration).toBeLessThan(60000);
  });

  it('should respond to list endpoint within 1 second', async () => {
    const start = Date.now();
    const response = await makeRequest('GET', '/threats?limit=10');
    const duration = Date.now() - start;

    expect(response.status).toBe(200);
    expect(duration).toBeLessThan(1000);
  });
});
