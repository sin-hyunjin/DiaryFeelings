import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'
import DarkMode from './Provider'
import Providers from './components/Providers'
import RefreshToken from './components/RefreshToken'
import NavBar from './components/Nav'

import Footerer from './components/Footerer'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'Create Next App',
  description: 'Generated by create next app',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={`${inter.className} flex flex-col w-full h-full items-center`}>
        <Providers>
          <RefreshToken />
          <DarkMode>
            <NavBar />
            {children}
            <Footerer />
          </DarkMode>
        </Providers>
      </body>
    </html>
  )
}
