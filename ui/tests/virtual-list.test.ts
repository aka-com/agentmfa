import test from 'node:test';
import assert from 'node:assert/strict';

import { virtualListWindow } from '../src/virtual-list';

const uniform = (count: number, height: number): number[] =>
  Array.from({ length: count }, () => height);

/** The window's spacers plus its mounted rows must always add up to the full
 * list height, or windowing would change how far the list scrolls. */
function assertHeightPreserved(heights: readonly number[], view: {
  start: number; end: number; padTop: number; padBottom: number;
}): void {
  const total = heights.reduce((sum, height) => sum + height, 0);
  const mounted = heights.slice(view.start, view.end).reduce((sum, height) => sum + height, 0);
  assert.equal(view.padTop + mounted + view.padBottom, total);
}

test('an empty list mounts nothing', () => {
  const view = virtualListWindow({
    heights: [], listTop: 0, scrollTop: 0, viewport: 500, overscan: 4,
  });
  assert.deepEqual(view, { start: 0, end: 0, padTop: 0, padBottom: 0 });
});

test('a list shorter than the viewport mounts every row without spacers', () => {
  const heights = uniform(6, 34);
  const view = virtualListWindow({
    heights, listTop: 0, scrollTop: 0, viewport: 500, overscan: 4,
  });

  assert.deepEqual(view, { start: 0, end: 6, padTop: 0, padBottom: 0 });
  assertHeightPreserved(heights, view);
});

test('a long list at rest mounts the viewport plus the overscan tail', () => {
  const heights = uniform(200, 34);
  const view = virtualListWindow({
    heights, listTop: 0, scrollTop: 0, viewport: 340, overscan: 5,
  });

  // Ten rows fill 340px; row 10 starts exactly at the fold, so it stays out.
  assert.equal(view.start, 0);
  assert.equal(view.end, 15);
  assert.equal(view.padTop, 0);
  assert.equal(view.padBottom, (200 - 15) * 34);
  assertHeightPreserved(heights, view);
});

test('scrolling mid-list mounts the visible rows and pads both ends', () => {
  const heights = uniform(200, 34);
  const view = virtualListWindow({
    heights, listTop: 0, scrollTop: 34 * 50, viewport: 340, overscan: 5,
  });

  assert.equal(view.start, 45);
  assert.equal(view.end, 65);
  assert.equal(view.padTop, 45 * 34);
  assertHeightPreserved(heights, view);
});

test('a partially scrolled row stays mounted', () => {
  const heights = uniform(200, 34);
  const view = virtualListWindow({
    heights, listTop: 0, scrollTop: 34 * 50 + 1, viewport: 340, overscan: 0,
  });

  // One pixel past row 50's top edge: row 50 is still on screen, and the row
  // that now peeks in at the bottom comes with it.
  assert.equal(view.start, 50);
  assert.equal(view.end, 61);
});

test('the list offset inside the scroller shifts the window', () => {
  const heights = uniform(200, 34);
  const filters = 120;
  const flush = virtualListWindow({
    heights, listTop: 0, scrollTop: 34 * 20 + filters, viewport: 340, overscan: 3,
  });
  const offset = virtualListWindow({
    heights, listTop: filters, scrollTop: 34 * 20 + filters, viewport: 340, overscan: 3,
  });

  // The same scroll offset lands further down a list that starts at the top of
  // the scroller than one pushed down by the filter row.
  assert.equal(offset.start, 17);
  assert.ok(flush.start > offset.start);
});

test('a list still below the fold mounts from its first row', () => {
  const heights = uniform(200, 34);
  const view = virtualListWindow({
    heights, listTop: 400, scrollTop: 0, viewport: 340, overscan: 2,
  });

  assert.equal(view.start, 0);
  assert.equal(view.padTop, 0);
});

test('variable row heights are honoured exactly', () => {
  // A tall detail row, then plain rows: the window must count real heights,
  // not a single estimate.
  const heights = [80, 34, 34, 55, 34, 34, 34, 34];
  const view = virtualListWindow({
    heights, listTop: 0, scrollTop: 148, viewport: 60, overscan: 0,
  });

  // 80 + 34 + 34 = 148, so row 3 (the 55px one) begins right at the fold; it
  // covers 55 of the 60 visible pixels, and row 4 peeks in below it.
  assert.equal(view.start, 3);
  assert.equal(view.end, 5);
  assert.equal(view.padTop, 148);
  assert.equal(view.padBottom, 34 * 3);
  assertHeightPreserved(heights, view);
});

test('overscan is clamped to the ends of the list', () => {
  const heights = uniform(20, 34);
  const top = virtualListWindow({
    heights, listTop: 0, scrollTop: 0, viewport: 68, overscan: 50,
  });
  const bottom = virtualListWindow({
    heights, listTop: 0, scrollTop: 34 * 18, viewport: 68, overscan: 50,
  });

  assert.deepEqual(top, { start: 0, end: 20, padTop: 0, padBottom: 0 });
  assert.deepEqual(bottom, { start: 0, end: 20, padTop: 0, padBottom: 0 });
});

test('a scroll offset past the end of the list still mounts the tail', () => {
  // The frame after a filter shortens the list: the scroller has not clamped
  // its offset yet. An empty window here would paint a blank strip.
  const heights = uniform(10, 34);
  const view = virtualListWindow({
    heights, listTop: 0, scrollTop: 9_000, viewport: 340, overscan: 0,
  });

  assert.equal(view.end, 10);
  assert.ok(view.start < view.end);
  assertHeightPreserved(heights, view);
});

test('an unmeasured viewport still mounts a row', () => {
  const heights = uniform(10, 34);
  const view = virtualListWindow({
    heights, listTop: 0, scrollTop: 0, viewport: 0, overscan: 0,
  });

  assert.deepEqual(view, { start: 0, end: 1, padTop: 0, padBottom: 34 * 9 });
});

test('unusable heights are treated as zero rather than poisoning the offsets', () => {
  const heights = [34, Number.NaN, -12, Number.POSITIVE_INFINITY, 34];
  const view = virtualListWindow({
    heights, listTop: 0, scrollTop: 0, viewport: 340, overscan: 0,
  });

  assert.deepEqual(view, { start: 0, end: 5, padTop: 0, padBottom: 0 });
});

test('the mounted window never exceeds the viewport plus overscan', () => {
  // The guarantee that makes windowing worth it: mounted rows scale with the
  // viewport, not with the log.
  const heights = uniform(5_000, 34);
  const view = virtualListWindow({
    heights, listTop: 0, scrollTop: 34 * 2_500, viewport: 680, overscan: 8,
  });

  assert.equal(view.end - view.start, 20 + 8 * 2);
  assertHeightPreserved(heights, view);
});
