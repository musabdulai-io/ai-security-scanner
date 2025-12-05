/**
 * Runtime environment access for Next.js frontend.
 * Uses window.__ENV for runtime config or falls back to process.env for build time.
 */

declare global {
  interface Window {
    __ENV?: Record<string, string>;
  }
}

export function getEnv(key: string): string {
  // Try runtime config first (injected via __env.js)
  if (typeof window !== 'undefined' && window.__ENV) {
    const value = window.__ENV[key];
    if (value) return value;
  }

  // Fall back to build-time environment variables
  const envValue = process.env[key];
  if (envValue) return envValue;

  // Default values
  const defaults: Record<string, string> = {
    NEXT_PUBLIC_API_URL: 'http://localhost:8000',
    NEXT_PUBLIC_SANDBOX_URL: 'https://rag-api.musabdulai.com',
  };

  return defaults[key] || '';
}
