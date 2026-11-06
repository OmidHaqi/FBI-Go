import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'

vi.mock('./bridge', () => ({ demoMode: true, iconData: vi.fn(), loadLiveData: vi.fn(), cliRead: vi.fn(), backendInfo: vi.fn(), removePolicy: vi.fn(), setPolicy: vi.fn() }))
import App from './App'

afterEach(cleanup)

describe('desktop presentation', () => {
  it('labels demo data and never presents a planned route as applied', () => {
    render(<App />)
    expect(screen.getByText('DEMO DATA')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Routing plans' }))
    expect(screen.getByText('NOT APPLIED')).toBeTruthy()
    expect(screen.getAllByText('PLAN_ONLY').length).toBeGreaterThan(0)
  })
  it('disables policy mutation in demo mode', () => {
    render(<App />)
    fireEvent.click(screen.getByRole('button', { name: 'Applications' }))
    fireEvent.click(screen.getByRole('button', { name: /Browser/ }))
    expect((screen.getByRole('button', { name: 'Save policy' }) as HTMLButtonElement).disabled).toBe(true)
  })
})
