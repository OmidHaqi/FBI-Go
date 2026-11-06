import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import { readFileSync } from 'node:fs'

const packageVersion = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')).version as string

export default defineConfig({
  plugins: [react()],
  define: { 'import.meta.env.VITE_APP_VERSION': JSON.stringify(packageVersion) },
  clearScreen: false,
  server: { host: '127.0.0.1', port: 1420, strictPort: true },
  envPrefix: ['VITE_'],
  test: { environment: 'jsdom', globals: true },
})
