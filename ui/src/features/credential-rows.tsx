import {
  useEffect, useLayoutEffect, useRef, useState,
} from 'react';
import type { ReactNode } from 'react';
import { virtualListWindow } from '../virtual-list';
import type { SecretSummary } from '../types';

// The same windowing recipe as ConnectedToolsList, tuned for the credential
// cards: rows are short and uniform except a tray row's inline expansion,
// which the per-row measurements absorb.
const OVERSCAN = 6;
const PREPAINT_VIEWPORT = 1200;
const HEIGHT_CACHE_MAX = 2_000;

interface ScrollMetrics {
  scrollTop: number;
  viewport: number;
  listTop: number;
  width: number;
}

const PREPAINT_METRICS: ScrollMetrics = {
  scrollTop: 0,
  viewport: PREPAINT_VIEWPORT,
  listTop: 0,
  width: 0,
};

/** Row measurements survive broker refreshes and filter flips by id. */
const rowHeights = new Map<string, number>();
let rowHeightsWidth = 0;

function readMetrics(scroller: Element, list: HTMLElement): ScrollMetrics {
  const scrollTop = scroller.scrollTop;
  return {
    scrollTop: Math.round(scrollTop),
    // A zero-height scroller is an unmeasured one (mid-layout, or a test
    // DOM with no layout at all); keep the generous prepaint estimate
    // rather than windowing the list down to a single row.
    viewport: Math.round(scroller.clientHeight) || PREPAINT_VIEWPORT,
    listTop: Math.round(
      list.getBoundingClientRect().top - scroller.getBoundingClientRect().top + scrollTop,
    ),
    // The list narrows as the split's inspector grows; measurements belong
    // to the row width they were taken at.
    width: Math.round(list.clientWidth),
  };
}

function sameMetrics(a: ScrollMetrics, b: ScrollMetrics): boolean {
  return a.scrollTop === b.scrollTop
    && a.viewport === b.viewport
    && a.listTop === b.listTop
    && a.width === b.width;
}

/**
 * A credential card's rows, windowed against the ancestor `.content`
 * scroller. `keepMountedId` pins one row into the mounted range — the
 * selected row so keyboard focus can land on it, or the tray's expanded
 * row so its copy actions survive a scroll.
 */
export function CredentialRowsList({
  secrets,
  className,
  rowEstimate,
  keepMountedId,
  renderRow,
}: {
  secrets: readonly SecretSummary[];
  className: string;
  rowEstimate: number;
  keepMountedId?: string | null;
  renderRow: (secret: SecretSummary) => ReactNode;
}): ReactNode {
  const listRef = useRef<HTMLDivElement | null>(null);
  const [metrics, setMetrics] = useState<ScrollMetrics>(PREPAINT_METRICS);
  const [, countMeasurements] = useState(0);

  const heights = secrets.map((secret) => rowHeights.get(secret.id) ?? rowEstimate);
  const view = virtualListWindow({
    heights,
    listTop: metrics.listTop,
    scrollTop: metrics.scrollTop,
    viewport: metrics.viewport,
    overscan: OVERSCAN,
  });
  const pinnedIndex = keepMountedId
    ? secrets.findIndex((secret) => secret.id === keepMountedId)
    : -1;
  const start = pinnedIndex >= 0 ? Math.min(view.start, pinnedIndex) : view.start;
  const end = pinnedIndex >= 0 ? Math.max(view.end, pinnedIndex + 1) : view.end;
  const padTop = heights.slice(0, start).reduce((sum, height) => sum + height, 0);
  const padBottom = heights.slice(end).reduce((sum, height) => sum + height, 0);

  useEffect(() => {
    const list = listRef.current;
    const scroller = list?.closest('.content');
    if (!list || !scroller) return;
    const sync = (): void => {
      const next = readMetrics(scroller, list);
      setMetrics((previous) => (sameMetrics(previous, next) ? previous : next));
    };
    sync();
    scroller.addEventListener('scroll', sync, { passive: true });
    const resize = new ResizeObserver(sync);
    resize.observe(scroller);
    return () => {
      scroller.removeEventListener('scroll', sync);
      resize.disconnect();
    };
  }, []);

  useLayoutEffect(() => {
    const list = listRef.current;
    const scroller = list?.closest('.content');
    if (!list || !scroller) return;

    const next = readMetrics(scroller, list);
    setMetrics((previous) => (sameMetrics(previous, next) ? previous : next));
    if (next.width && next.width !== rowHeightsWidth) {
      rowHeightsWidth = next.width;
      rowHeights.clear();
    }
    if (rowHeights.size > HEIGHT_CACHE_MAX) rowHeights.clear();

    const mounted = list.querySelectorAll<HTMLElement>(':scope > [data-secret-row]');
    let changed = false;
    mounted.forEach((element, index) => {
      const secret = secrets[start + index];
      if (!secret) return;
      const height = element.getBoundingClientRect().height;
      const known = rowHeights.get(secret.id);
      if (height > 0 && (known === undefined || Math.abs(known - height) > 0.5)) {
        rowHeights.set(secret.id, height);
        changed = true;
      }
    });
    if (changed) countMeasurements((count) => count + 1);
  });

  return (
    <div ref={listRef} className={className}>
      {padTop > 0
        ? <div className="tool-list-pad" style={{ height: padTop }} aria-hidden="true" />
        : null}
      {secrets.slice(start, end).map(renderRow)}
      {padBottom > 0
        ? <div className="tool-list-pad" style={{ height: padBottom }} aria-hidden="true" />
        : null}
    </div>
  );
}
