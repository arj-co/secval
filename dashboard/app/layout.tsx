import './globals.css';
import React from 'react';

export const metadata = {
  title: 'Zero-Trust Agent Security Benchmark & Policy Enforcement Platform',
  description: 'Automated evaluation, provenance tracking, Cedar policy enforcement, and agentic policy repair for AI agents.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>{children}</body>
    </html>
  );
}
