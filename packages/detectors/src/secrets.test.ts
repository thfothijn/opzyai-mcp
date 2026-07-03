import { describe, it, expect } from 'vitest';
import { analyzeBundleSecrets } from './index';

// Assembled at runtime so no contiguous key-shaped string ever exists in this
// file's source or git history (keeps our own scanner and GitHub secret
// scanning quiet on this repo).
const FAKE_STRIPE_KEY = ['sk_live', 'abcdEFGH1234567890'].join('_');

describe('analyzeBundleSecrets', () => {
  it('flags a Stripe secret key and redacts it', () => {
    const out = analyzeBundleSecrets(`const k = "${FAKE_STRIPE_KEY}";`, 'app.js');
    expect(out).toHaveLength(1);
    expect(out[0]?.signature).toBe('leaked-secret:stripe-secret');
    expect(out[0]?.severity).toBe('critical');
    expect(out[0]?.evidence).not.toContain(FAKE_STRIPE_KEY); // redacted
  });
  it('does NOT flag a Stripe publishable key', () => {
    expect(analyzeBundleSecrets('pk_live_abcdEFGH1234567890', 'app.js')).toHaveLength(0);
  });
});
