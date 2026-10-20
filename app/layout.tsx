import type { Metadata } from 'next';
import { Geist, Geist_Mono } from 'next/font/google';
import './globals.css';

const geistSans = Geist({ variable: '--font-geist-sans', subsets: ['latin'] });
const geistMono = Geist_Mono({ variable: '--font-geist-mono', subsets: ['latin'] });

export const metadata: Metadata = {
  metadataBase: new URL('http://localhost:3000'),
  title: 'AI-CSI Evidence Console',
  description: 'Cybersecurity log investigation and attack reconstruction prototype.',
  openGraph: {
    title: 'AI-CSI Evidence Console',
    description: 'Cybersecurity log investigation and attack reconstruction.',
    images: ['/og.png'],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'AI-CSI Evidence Console',
    description: 'Cybersecurity log investigation and attack reconstruction.',
    images: ['/og.png'],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable} antialiased`}>{children}</body>
    </html>
  );
}
