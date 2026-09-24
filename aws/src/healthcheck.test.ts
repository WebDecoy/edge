import { healthNonce } from './index';

describe('healthNonce (deploy verification querystring parse)', () => {
  it('extracts the nonce when present', () => {
    expect(healthNonce('__wd_clearance_check=abc123')).toBe('abc123');
  });

  it('extracts it among other params', () => {
    expect(healthNonce('foo=1&__wd_clearance_check=xyz&bar=2')).toBe('xyz');
  });

  it('URL-decodes the value', () => {
    expect(healthNonce('__wd_clearance_check=a%20b')).toBe('a b');
  });

  it('returns "" for the param with no value', () => {
    expect(healthNonce('__wd_clearance_check')).toBe('');
  });

  it('returns null when absent', () => {
    expect(healthNonce('foo=1&bar=2')).toBeNull();
    expect(healthNonce('')).toBeNull();
  });

  it('does not match a param that merely contains the name', () => {
    expect(healthNonce('x__wd_clearance_check=1')).toBeNull();
  });
});
