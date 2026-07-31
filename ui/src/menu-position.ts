export interface MenuRect {
  left: number;
  top: number;
  right: number;
  bottom: number;
}

export interface MenuSize {
  width: number;
  height: number;
}

export interface ViewportSize {
  width: number;
  height: number;
}

/**
 * Right-align a menu to its trigger and keep every edge inside the viewport.
 * Prefer opening below, flip above when that is the only side that fits, and
 * clamp as a final fallback for menus taller than either available side.
 */
export function anchoredMenuPosition(
  anchor: MenuRect,
  menu: MenuSize,
  viewport: ViewportSize,
  gap = 4,
  inset = 8,
): { left: number; top: number } {
  const maxLeft = Math.max(inset, viewport.width - menu.width - inset);
  const left = Math.min(Math.max(inset, anchor.right - menu.width), maxLeft);

  const below = anchor.bottom + gap;
  const above = anchor.top - menu.height - gap;
  const fitsBelow = below + menu.height <= viewport.height - inset;
  const fitsAbove = above >= inset;
  const preferredTop = fitsBelow || !fitsAbove ? below : above;
  const maxTop = Math.max(inset, viewport.height - menu.height - inset);
  const top = Math.min(Math.max(inset, preferredTop), maxTop);

  return { left, top };
}
