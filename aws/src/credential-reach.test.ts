import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The Lambda@Edge validator has no notion of where a credential may grant
 * access (#1121), and that is safe for exactly one reason: the backend never
 * serves it a restricted credential. Restricted credentials travel in
 * `restricted_credentials`, and this build grants access only from
 * `active_credentials`, which they are never in.
 *
 * This test reads the source, because the property it protects is an absence.
 * The failure it exists to stop is someone adding half of reach here -- taking
 * the ids from the new field without applying the reach -- which would grant a
 * restricted credential access everywhere, silently, on every AWS deployment.
 * Add reach properly (see #1126) and this test should be replaced by one that
 * exercises it.
 */

const source = readFileSync(join(__dirname, 'index.ts'), 'utf8');

describe('the Lambda cannot grant a restricted credential', () => {
  it('never reads the field restricted credentials travel in', () => {
    expect(source).not.toContain('restricted_credentials');
  });

  it('grants a machine token only from the unrestricted list', () => {
    const machineBranch = source.slice(source.indexOf('1. Machine service token'), source.indexOf('2. Verified crawler'));
    expect(machineBranch).toContain('config.active_credentials.includes(claims.sub)');
    expect(machineBranch.match(/config\.\w+\.includes/g)).toEqual(['config.active_credentials.includes']);
  });
});
