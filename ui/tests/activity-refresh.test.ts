import assert from 'node:assert/strict';
import test from 'node:test';
import { refreshActivityPages } from '../src/activity-refresh';
import type { ActivityEntry, ActivityPage } from '../src/types';

function entries(prefix: string, count: number): ActivityEntry[] {
  return Array.from({ length: count }, (_, index) => ({
    icon: 'test',
    tone: 'muted',
    at: `2026-07-30T00:${String(index % 60).padStart(2, '0')}:00Z`,
    kind: 'test',
    text: `${prefix}-${index}`,
    detail: null,
  }));
}

test('activity refresh preserves the number of historical pages already loaded', async () => {
  const calls: Array<number | null> = [];
  const pages: Record<number, ActivityPage> = {
    0: { entries: entries('new', 500), next_before: 1 },
    1: { entries: entries('old', 500), next_before: 2 },
    2: { entries: entries('older', 100), next_before: null },
  };
  const refreshed = await refreshActivityPages(1_000, true, async (before) => {
    calls.push(before);
    return pages[before ?? 0];
  });
  assert.deepEqual(calls, [null, 1]);
  assert.equal(refreshed.entries.length, 1_000);
  assert.equal(refreshed.next_before, 2);
});

test('activity clear refresh intentionally returns to one page', async () => {
  let calls = 0;
  const refreshed = await refreshActivityPages(1_000, false, async () => {
    calls += 1;
    return { entries: [], next_before: null };
  });
  assert.equal(calls, 1);
  assert.deepEqual(refreshed.entries, []);
});

test('activity refresh fetches only the non-page-aligned remainder', async () => {
  const limits: number[] = [];
  const refreshed = await refreshActivityPages(1_001, true, async (before, limit) => {
    limits.push(limit);
    const page = before ?? 0;
    return {
      entries: entries(`page-${page}`, limit),
      next_before: page + 1,
    };
  });
  assert.deepEqual(limits, [500, 500, 1]);
  assert.equal(refreshed.entries.length, 1_001);
  assert.equal(refreshed.next_before, 3);
});
