import type { OnePasswordField, OnePasswordItem, OnePasswordVault } from './types';

export const ONEPASSWORD_ALIAS_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function onePasswordFieldKey(field: OnePasswordField): string {
  return `${field.section_id ?? ''}:${field.id}`;
}

export function onePasswordFieldIsUnsupported(field: OnePasswordField): boolean {
  const fieldType = field.field_type.trim().toLowerCase();
  return fieldType === 'unsupported' || fieldType === 'unknown';
}

export function onePasswordSelectionKey(
  vault: OnePasswordVault,
  item: OnePasswordItem,
  field: OnePasswordField,
): string {
  return `${vault.id}:${item.id}:${onePasswordFieldKey(field)}`;
}

function aliasPart(value: string): string {
  return value.trim().toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '');
}

export function suggestedOnePasswordAlias(
  item: OnePasswordItem,
  field: OnePasswordField,
  unavailable: Iterable<string>,
): string {
  const stem = [item.title, field.section_title, field.title]
    .map((value) => aliasPart(value ?? ''))
    .filter(Boolean)
    .join('_') || 'ONEPASSWORD_SECRET';
  const safeStem = /^[A-Z_]/.test(stem) ? stem : `_${stem}`;
  const occupied = new Set(Array.from(unavailable, (name) => name.toUpperCase()));
  if (!occupied.has(safeStem)) return safeStem.slice(0, 64);
  for (let suffix = 2; suffix < 10_000; suffix += 1) {
    const candidate = `${safeStem.slice(0, 64 - String(suffix).length - 1)}_${suffix}`;
    if (!occupied.has(candidate)) return candidate;
  }
  return safeStem.slice(0, 59) + '_LINK';
}

export function onePasswordAliasError(alias: string, unavailable: Iterable<string>): string | null {
  const trimmed = alias.trim();
  if (!trimmed) return 'Stored name is required';
  if (trimmed.length > 64) return 'Use 64 characters or fewer';
  if (!ONEPASSWORD_ALIAS_PATTERN.test(trimmed)) {
    return 'Use letters, numbers, and underscores; start with a letter or underscore';
  }
  const occupied = new Set(Array.from(unavailable, (name) => name.toUpperCase()));
  if (occupied.has(trimmed.toUpperCase())) return 'That stored name is already in use';
  return null;
}
