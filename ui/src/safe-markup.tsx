import DOMPurify from 'dompurify';
import parse, {
  attributesToProps,
  domToReact,
  Element as ParsedElement,
} from 'html-react-parser';
import type { DOMNode, HTMLReactParserOptions } from 'html-react-parser';
import { createElement, useMemo } from 'react';
import type { ReactNode } from 'react';

/**
 * Compatibility boundary for the remaining read-mostly HTML renderers.
 *
 * Markup is sanitized, parsed into React elements, and reconciled in place—
 * never assigned to innerHTML. Forms belong in controlled TSX components;
 * the input handling below is a safety net that keeps any future legacy input
 * uncontrolled. Stable ids key rows so reorders move DOM nodes instead of
 * rewriting their positions.
 */
export function SafeMarkup({ markup }: { markup: string }): ReactNode {
  const clean = useMemo(() => {
    const out = String(DOMPurify.sanitize(markup, {
      USE_PROFILES: { html: true, svg: true, svgFilters: true },
      // focusable is the SVG a11y attribute keeping icons out of tab order;
      // the profiles don't know it and would silently strip it.
      ADD_ATTR: ['data-tauri-drag-region', 'focusable'],
    }));
    // Surface unexpected sanitizer removals during the Vite development build.
    if (import.meta.env?.DEV && DOMPurify.removed.length) {
      console.warn('SafeMarkup: sanitizer dropped markup', DOMPurify.removed);
    }
    return out;
  }, [markup]);

  const nodes = useMemo(() => {
    const options: HTMLReactParserOptions = {
      replace(node) {
        if (!(node instanceof ParsedElement)) return;
        if (node.name === 'input' || node.name === 'textarea') {
          const props = attributesToProps(node.attribs) as Record<string, unknown>;
          if ('value' in props) {
            props.defaultValue = props.value;
            delete props.value;
          }
          if ('checked' in props) {
            props.defaultChecked = props.checked;
            delete props.checked;
          }
          // A textarea's text children are its default value; passing both
          // them and defaultValue trips React's invariant.
          if (node.name === 'textarea' && node.children.length) delete props.defaultValue;
          const identity = node.attribs.id ?? node.attribs.name;
          if (identity) props.key = identity;
          return createElement(
            node.name,
            props,
            node.name === 'textarea'
              ? domToReact(node.children as DOMNode[], options)
              : undefined,
          );
        }

        const rowKey = node.attribs['data-id'] ?? node.attribs.id;
        if (rowKey) {
          // Sibling action buttons can share one row id; the action name keeps
          // their React keys distinct.
          const act = node.attribs['data-act'];
          return createElement(
            node.name,
            { ...attributesToProps(node.attribs), key: `${node.name}:${act ?? ''}:${rowKey}` },
            node.children.length
              ? domToReact(node.children as DOMNode[], options)
              : undefined,
          );
        }
        return;
      },
    };
    return parse(clean, options);
  }, [clean]);

  return nodes;
}
