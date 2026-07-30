import type { ConnectionType } from './types';

export type FormErrors = Record<string, string>;

export function validateSecretForm(input: {
  adding: boolean;
  name: string;
  value: string;
  valueModified: boolean;
}): FormErrors {
  const errors: FormErrors = {};
  if (!input.name.trim()) errors.name = 'Name is required';
  if (input.adding && !input.value) errors.value = 'Value is required';
  if (!input.adding && input.valueModified && !input.value) {
    errors.value = 'Invalid value';
  }
  return errors;
}

export interface ConnectionValidationInput {
  adding: boolean;
  type: ConnectionType;
  name: string;
  host?: string | null;
  port?: string;
  dbname?: string | null;
  user: string;
  oauthClientRequired: boolean;
  oauthClientId?: string;
  oauthUrls?: {
    auth?: string;
    token?: string;
  };
  needsCredentialChoice: boolean;
  secretSource: 'existing' | 'new' | 'none';
  selectedSecretPresent: boolean;
  newSecretName?: string | null;
  newSecretValue?: string | null;
  hasImportedIdentity: boolean;
  advancedTemplateRequired: boolean;
  injectionTemplate: string;
  editingTemplateRequired: boolean;
}

export interface ConnectionValidation {
  errors: FormErrors;
  port: number;
}

export interface EndpointTarget {
  type: ConnectionType;
  scheme?: string | null;
  host?: string | null;
  port?: number | null;
  dbname?: string | null;
  user?: string | null;
  destination?: string | null;
  mcpPath?: string | null;
  hostKeyFingerprint?: string | null;
}

export function retargetsIssuedEndpoint(
  current: EndpointTarget,
  next: EndpointTarget | null,
): boolean {
  if (!next || current.type !== next.type) return false;
  const changed = (...fields: Array<keyof EndpointTarget>) =>
    fields.some((field) => (current[field] ?? null) !== (next[field] ?? null));
  if (current.type === 'pg') return changed('host', 'port', 'dbname', 'user');
  if (current.type === 'ssh') {
    return changed('host', 'port', 'user', 'hostKeyFingerprint');
  }
  if (current.type === 'api') return changed('scheme', 'host', 'port');
  return false;
}

export function validateConnectionForm(
  input: ConnectionValidationInput,
): ConnectionValidation {
  const errors: FormErrors = {};
  if (!input.name.trim()) errors.name = 'Name is required';
  if ((input.type === 'pg' || input.type === 'ssh') && !(input.host || '').trim()) {
    errors.host = 'Host is required';
  }

  const defaultPort = input.type === 'ssh' ? 22 : 5432;
  const portText = (input.port ?? '').trim() || String(defaultPort);
  const port = Number(portText);
  if (
    (input.type === 'pg' || input.type === 'ssh')
    && (!/^\d+$/.test(portText) || !Number.isInteger(port) || port < 1 || port > 65535)
  ) {
    errors.port = 'Port must be 1–65535';
  }
  if (input.type === 'pg' && !(input.dbname || '').trim()) {
    errors.dbname = 'Database is required';
  }
  if ((input.type === 'pg' || input.type === 'ssh') && !input.user.trim()) {
    errors.user = 'User is required';
  }

  if (input.oauthClientRequired && !(input.oauthClientId || '').trim()) {
    errors.oauthClientId = 'The OAuth client ID is required';
  }
  if (input.oauthUrls) {
    if (!/^https:\/\//.test((input.oauthUrls.auth || '').trim())) {
      errors.oauthAuthUrl = 'Must be a complete https:// URL';
    }
    if (!/^https:\/\//.test((input.oauthUrls.token || '').trim())) {
      errors.oauthTokenUrl = 'Must be a complete https:// URL';
    }
  }

  if (input.needsCredentialChoice && input.secretSource === 'existing'
      && !input.selectedSecretPresent) {
    errors.secret = 'Choose a saved credential or save a new one';
  }
  if (input.needsCredentialChoice && input.secretSource === 'new') {
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(input.newSecretName || '')) {
      errors.newSecretName =
        'Use letters, numbers, and underscores; start with a letter or underscore';
    }
    if (!input.newSecretValue && !input.hasImportedIdentity) {
      errors.newSecretValue = 'Credential value is required';
    }
  }

  if (
    (input.advancedTemplateRequired || input.editingTemplateRequired)
    && !input.injectionTemplate
  ) {
    errors.template = 'Credential template is required';
  }
  return { errors, port };
}
