import type { ActivityPage } from './types';

export const ACTIVITY_PAGE_LIMIT = 500;

export async function refreshActivityPages(
  currentCount: number,
  preserveDepth: boolean,
  fetchPage: (before: number | null, limit: number) => Promise<ActivityPage>,
): Promise<ActivityPage> {
  const targetCount = preserveDepth
    ? Math.max(ACTIVITY_PAGE_LIMIT, currentCount)
    : ACTIVITY_PAGE_LIMIT;
  const entries: ActivityPage['entries'] = [];
  let before: number | null = null;
  let nextBefore: number | null = null;
  const seenCursors = new Set<number>();

  do {
    const remaining = Math.max(1, targetCount - entries.length);
    const page = await fetchPage(before, Math.min(ACTIVITY_PAGE_LIMIT, remaining));
    entries.push(...page.entries);
    nextBefore = page.next_before ?? null;
    if (!nextBefore || entries.length >= targetCount || seenCursors.has(nextBefore)) break;
    seenCursors.add(nextBefore);
    before = nextBefore;
  } while (true);

  return { entries, next_before: nextBefore };
}
