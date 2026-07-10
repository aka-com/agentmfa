// Pure helpers for routing structured backend form errors. Keeping this out
// of app.js makes the IPC contract testable without a browser.

function structuredError(error) {
  if (error && typeof error === 'object' && typeof error.message === 'string') return error;
  if (typeof error === 'string') {
    try {
      const parsed = JSON.parse(error);
      if (parsed && typeof parsed === 'object' && typeof parsed.message === 'string') return parsed;
    } catch {
      // A legacy/plain-string Tauri error remains a global message.
    }
  }
  return null;
}

export function inlineFormError(error) {
  const parsed = structuredError(error);
  if (!parsed || !parsed.field) return null;
  if (parsed.kind !== 'validation' && parsed.kind !== 'conflict') return null;
  return { field: parsed.field, message: parsed.message };
}

export function formErrorMessage(error) {
  const parsed = structuredError(error);
  if (parsed) return parsed.message;
  if (error instanceof Error) return error.message;
  return String(error || 'Couldn’t save your changes');
}

export function formErrorKind(error) {
  return structuredError(error)?.kind || null;
}
