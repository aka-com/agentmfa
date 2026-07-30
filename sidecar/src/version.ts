declare const __AGENTMFA_SIDECAR_VERSION__: string;

/** Stamped from the Cargo workspace version by the sidecar build. */
export const SIDECAR_VERSION =
  typeof __AGENTMFA_SIDECAR_VERSION__ === 'string'
    ? __AGENTMFA_SIDECAR_VERSION__
    : 'development';
