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
  it('suppresses the WebView context menu without blocking text input', () => {
    render(<App />)
    fireEvent.click(screen.getByRole('button', { name: 'Applications' }))
    const input = screen.getByRole('textbox', { name: 'Search applications' }) as HTMLInputElement
    fireEvent.change(input, { target: { value: 'browser' } })
    expect(input.value).toBe('browser')
    const event = new MouseEvent('contextmenu', { bubbles: true, cancelable: true })
    input.dispatchEvent(event)
    expect(event.defaultPrevented).toBe(true)
    for (const key of ['a', 'c', 'v', 'x']) {
      const shortcut = new KeyboardEvent('keydown', { key, ctrlKey: true, bubbles: true, cancelable: true })
      input.dispatchEvent(shortcut)
      expect(shortcut.defaultPrevented).toBe(false)
    }
  })
})
