import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import type { LiveData } from './bridge'

const loadLiveData = vi.hoisted(() => vi.fn<() => Promise<LiveData>>())
vi.mock('./bridge', () => ({
  demoMode: false,
  iconData: vi.fn(),
  loadLiveData,
  cliRead: vi.fn(),
  backendInfo: vi.fn(),
  removePolicy: vi.fn(),
  setPolicy: vi.fn(),
}))
import App from './App'

afterEach(() => {
  cleanup()
  loadLiveData.mockReset()
})

describe('live desktop state', () => {
  it('shows loading before a read and an actionable empty state when the daemon is offline', async () => {
    let complete!: (value: LiveData) => void
    loadLiveData.mockReturnValue(new Promise(resolve => { complete = resolve }))
    render(<App />)
    expect(screen.getByText('Loading read-only backend data…')).toBeTruthy()
    complete({ apps: [], policies: [], errors: ['Daemon connection: socket unavailable'] })
    expect(await screen.findByText('No interface data')).toBeTruthy()
    expect(screen.getByText('DAEMON OFFLINE')).toBeTruthy()
    expect(screen.getByText(/Some backend data is unavailable/)).toBeTruthy()
  })
})
