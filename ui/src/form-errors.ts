// Pure helpers for routing structured backend form errors. Keeping this out
// of app.tsx makes the IPC contract testable without a browser.

export interface StructuredFormError {
  kind?: string;
  code?: string;
  field?: string;
  message: string;
}

function isStructuredFormError(error: unknown): error is StructuredFormError {
  return typeof error === 'object' && error !== null &&
    'message' in error && typeof error.message === 'string';
}

function structuredError(error: unknown): StructuredFormError | null {
  if (isStructuredFormError(error)) return error;
  if (typeof error === 'string') {
    try {
      const parsed = JSON.parse(error);
      if (isStructuredFormError(parsed)) return parsed;
    } catch {
      // A legacy/plain-string Tauri error remains a global message.
    }
  }
  return null;
}

export function inlineFormError(error: unknown): { field: string; message: string } | null {
  const parsed = structuredError(error);
  if (!parsed || !parsed.field) return null;
  if (parsed.kind !== 'validation' && parsed.kind !== 'conflict') return null;
  return { field: parsed.field, message: parsed.message };
}

export function formErrorMessage(error: unknown): string {
  const parsed = structuredError(error);
  if (parsed) return parsed.message;
  if (error instanceof Error) return error.message;
  return String(error || 'Couldn’t save your changes');
}

export function formErrorKind(error: unknown): string | null {
  return structuredError(error)?.kind || null;
}
