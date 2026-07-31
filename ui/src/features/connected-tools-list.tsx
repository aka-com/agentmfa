import {
  useEffect, useLayoutEffect, useRef, useState,
} from 'react';
import type { ReactNode } from 'react';
import { virtualListWindow } from '../virtual-list';

const OVERSCAN = 6;
const PREPAINT_VIEWPORT = 1200;
const ROW_ESTIMATE = 61;
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

/** Row measurements survive broker refreshes and reorder previews by id. */
const rowHeights = new Map<string, number>();
let rowHeightsWidth = 0;

function readMetrics(scroller: Element, list: HTMLElement): ScrollMetrics {
  const scrollTop = scroller.scrollTop;
  return {
    scrollTop: Math.round(scrollTop),
    viewport: Math.round(scroller.clientHeight),
    listTop: Math.round(
      list.getBoundingClientRect().top - scroller.getBoundingClientRect().top + scrollTop,
    ),
    // The master list narrows when the detail pane opens even though its
    // ancestor scroller does not. Measurements belong to the row width.
    width: Math.round(list.clientWidth),
  };
}

function sameMetrics(a: ScrollMetrics, b: ScrollMetrics): boolean {
  return a.scrollTop === b.scrollTop
    && a.viewport === b.viewport
    && a.listTop === b.listTop
    && a.width === b.width;
}

export interface ConnectedToolListItem {
  id: string;
}

/**
 * The connected Tools rows, windowed against their ancestor `.content`
 * scroller.
 *
 * Dragging deliberately mounts every row. Native drag sources cannot be
 * safely unmounted mid-gesture, and exact drop ordering needs every row's
 * midpoint. Ordinary search, refresh, selection, and health updates retain
 * the bounded window.
 */
export function ConnectedToolsList<T extends ConnectedToolListItem>({
  items,
  reorderable,
  dragging,
  keepMountedId,
  renderItem,
}: {
  items: readonly T[];
  reorderable: boolean;
  dragging: boolean;
  /** A row being moved by keyboard must survive the reorder render. */
  keepMountedId?: string | null;
  renderItem: (item: T) => ReactNode;
}): ReactNode {
  const listRef = useRef<HTMLDivElement | null>(null);
  const [metrics, setMetrics] = useState<ScrollMetrics>(PREPAINT_METRICS);
  const [, countMeasurements] = useState(0);

  const heights = items.map((item) => rowHeights.get(item.id) ?? ROW_ESTIMATE);
  const view = virtualListWindow({
    heights,
    listTop: metrics.listTop,
    scrollTop: metrics.scrollTop,
    viewport: metrics.viewport,
    overscan: OVERSCAN,
  });
  const pinnedIndex = keepMountedId
    ? items.findIndex((item) => item.id === keepMountedId)
    : -1;
  const start = dragging ? 0
    : pinnedIndex >= 0 ? Math.min(view.start, pinnedIndex)
    : view.start;
  const end = dragging ? items.length
    : pinnedIndex >= 0 ? Math.max(view.end, pinnedIndex + 1)
    : view.end;
  const padTop = dragging ? 0 : heights.slice(0, start).reduce((sum, height) => sum + height, 0);
  const padBottom = dragging ? 0
    : heights.slice(end).reduce((sum, height) => sum + height, 0);

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

    const mounted = list.querySelectorAll<HTMLElement>(':scope > .flat-conn-wrap');
    let changed = false;
    mounted.forEach((element, index) => {
      const item = items[start + index];
      if (!item) return;
      const height = element.getBoundingClientRect().height;
      const known = rowHeights.get(item.id);
      if (height > 0 && (known === undefined || Math.abs(known - height) > 0.5)) {
        rowHeights.set(item.id, height);
        changed = true;
      }
    });
    if (changed) countMeasurements((count) => count + 1);
  });

  return (
    <div ref={listRef}
      className={`cat-rows${reorderable ? ' reorderable' : ''}${dragging ? ' drag-active' : ''}`}
      data-conn-list={reorderable ? 'on' : ''}>
      {padTop > 0
        ? <div className="tool-list-pad" style={{ height: padTop }} aria-hidden="true" />
        : null}
      {items.slice(start, end).map(renderItem)}
      {padBottom > 0
        ? <div className="tool-list-pad" style={{ height: padBottom }} aria-hidden="true" />
        : null}
    </div>
  );
}
