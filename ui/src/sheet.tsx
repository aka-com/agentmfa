import { useLayoutEffect, useRef } from 'react';
import type { ReactNode } from 'react';

const FOCUSABLE_SELECTOR =
  'button:not([disabled]), input:not([disabled]), select:not([disabled]), summary';

interface SheetProps {
  titleId: string;
  children: ReactNode;
  className?: string;
  role?: 'dialog' | 'alertdialog';
  backdropAction?: string;
  backdropClassName?: string;
}

interface IsolationState {
  count: number;
  inert: boolean;
  ariaHidden: string | null;
}

const surfaceIsolation = new WeakMap<HTMLElement, IsolationState>();

function isolate(element: HTMLElement): () => void {
  let isolation = surfaceIsolation.get(element);
  if (!isolation) {
    isolation = {
      count: 0,
      inert: element.inert === true,
      ariaHidden: element.getAttribute('aria-hidden'),
    };
    surfaceIsolation.set(element, isolation);
  }
  isolation.count += 1;
  element.inert = true;
  element.setAttribute('aria-hidden', 'true');

  return () => {
    const current = surfaceIsolation.get(element);
    if (!current) return;
    current.count -= 1;
    if (current.count > 0) return;
    element.inert = current.inert;
    if (current.ariaHidden === null) element.removeAttribute('aria-hidden');
    else element.setAttribute('aria-hidden', current.ariaHidden);
    surfaceIsolation.delete(element);
  };
}

/**
 * Shared modal boundary for every sheet.
 *
 * Besides the dialog semantics, this owns the two modal behaviors that a
 * keyboard focus trap alone cannot provide: hiding the application surface
 * from browse-mode navigation and returning focus to the control that opened
 * the sheet.
 */
export function Sheet({
  titleId,
  children,
  className = '',
  role = 'dialog',
  backdropAction = 'sheet-cancel',
  backdropClassName = '',
}: SheetProps): ReactNode {
  const dialogRef = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    const surface = document.querySelector<HTMLElement>('.surface');
    const opener = document.activeElement instanceof HTMLElement
      && document.activeElement !== document.body
      ? document.activeElement
      : null;
    const releaseSurface = surface ? isolate(surface) : () => {};
    // A confirmation may stack over a form sheet. Make every earlier modal
    // inert as well so browse-mode navigation reaches only the top layer.
    const backgroundSheets = Array.from(
      document.querySelectorAll<HTMLElement>('.sheet[role="dialog"], .sheet[role="alertdialog"]'),
    ).filter((candidate) => candidate !== dialogRef.current);
    const releaseBackgroundSheets = backgroundSheets.map(isolate);

    const initial = dialogRef.current?.querySelector<HTMLElement>('[data-sheet-autofocus="true"]')
      ?? dialogRef.current?.querySelector<HTMLElement>(FOCUSABLE_SELECTOR)
      ?? dialogRef.current;
    initial?.focus();

    return () => {
      for (const release of releaseBackgroundSheets.reverse()) release();
      releaseSurface();
      // Sibling modal cleanups may still be restoring their isolation state
      // in this commit. Return focus after all of them have completed.
      queueMicrotask(() => {
        if (opener?.isConnected) opener.focus();
      });
    };
  }, []);

  return (
    <>
      <div className={`sheet-backdrop ${backdropClassName}`.trim()}
        data-act={backdropAction}></div>
      <div ref={dialogRef} className={`sheet ${className}`.trim()} role={role}
        aria-modal="true" aria-labelledby={titleId} tabIndex={-1}>
        {children}
      </div>
    </>
  );
}
