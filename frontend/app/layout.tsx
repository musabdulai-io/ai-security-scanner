import type { Metadata } from 'next';
import Script from 'next/script';
import { Providers } from './providers';

export const metadata: Metadata = {
  title: 'AI Security Scanner | Musah Abdulai',
  description: 'Audit LLM and RAG applications for security vulnerabilities',
  authors: [{ name: 'Musah Abdulai', url: 'https://musabdulai.com' }],
  openGraph: {
    title: 'AI Security Scanner | Musah Abdulai',
    description: 'Audit LLM and RAG applications for security vulnerabilities',
    url: 'https://audit.musabdulai.com',
    type: 'website',
  },
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
