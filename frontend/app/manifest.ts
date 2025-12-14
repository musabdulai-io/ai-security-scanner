import type { MetadataRoute } from 'next';

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: 'AI Security Scanner',
    short_name: 'AI Scanner',
    description: 'Audit LLM and RAG applications for security vulnerabilities',
    start_url: '/',
    display: 'standalone',
    background_color: '#faf9f7',
    theme_color: '#00ff88',
    icons: [
      { src: '/web-app-manifest-192x192.png', sizes: '192x192', type: 'image/png' },
      { src: '/web-app-manifest-512x512.png', sizes: '512x512', type: 'image/png' },
    ],
  };
}
