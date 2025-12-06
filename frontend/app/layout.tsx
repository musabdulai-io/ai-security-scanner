import type { Metadata } from 'next';
import Script from 'next/script';
import { Providers } from './providers';

export const metadata: Metadata = {
  title: 'AI Security Scanner',
  description: 'Audit LLM and RAG applications for security vulnerabilities',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang='en'>
      <head>
        <Script src='/runtime-env.js' strategy='beforeInteractive' />
      </head>
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
