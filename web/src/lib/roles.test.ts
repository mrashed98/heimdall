import { expect, it } from 'vitest';
import { isAdmin } from './roles';
it('shows administration only to principals with an admin grant', () => {
  expect(isAdmin([{ role: 'editor', realm: '*' }])).toBe(false);
  expect(isAdmin([{ role: 'admin', realm: '*' }])).toBe(true);
});
