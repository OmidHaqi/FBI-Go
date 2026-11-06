import { describe, expect, it, vi } from 'vitest'
import { isReadMethod, loadLiveData, validCapabilities, validPlan, validStatus } from './bridge'

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(async (command: string, args?: { method?: string; kind?: string }) => {
    if (command === 'backend_info') return { socket: '/tmp/private/control.sock', cli: '/bin/fbi', host_apply: 'UNSUPPORTED' }
    if (command === 'cli_read' && args?.kind === 'apps') return []
    if (command === 'cli_read' && args?.kind === 'policies') return []
    if (command === 'daemon_read' && args?.method === 'daemon.capabilities') return { mode: 'PLAN_ONLY', read_only: ['daemon.status', 'daemon.diagnostics'], host_apply: 'UNSUPPORTED' }
    if (command === 'daemon_read' && args?.method === 'daemon.status') return { state: 'PLANNED', mode: 'PLAN_ONLY', applied: false, snapshot: { devices: [], routes: [] } }
    if (command === 'daemon_read' && args?.method === 'daemon.diagnostics') return { read_only: true, findings: [] }
    throw new Error('unexpected request')
  }),
}))

describe('version 1 desktop bridge', () => {
  it('rejects mutation method names', () => {
    expect(isReadMethod('daemon.status')).toBe(true)
    expect(isReadMethod('daemon.apply')).toBe(false)
    expect(isReadMethod('HOST_APPLY')).toBe(false)
  })
  it('rejects backend claims of host apply or applied plans', () => {
    expect(validCapabilities({ mode: 'PLAN_ONLY', read_only: ['daemon.status'], host_apply: 'SUPPORTED' })).toBe(false)
    expect(validStatus({ state: 'PLANNED', mode: 'PLAN_ONLY', applied: true, snapshot: { devices: [], routes: [] } })).toBe(false)
    expect(validPlan({ state: 'PLANNED', mode: 'PLAN_ONLY', applied: true, proposed_resources: {}, conflicts: [], warnings: [] })).toBe(false)
  })
  it('uses capability discovery and reports unavailable methods', async () => {
    const result = await loadLiveData()
    expect(result.status?.applied).toBe(false)
    expect(result.capabilities?.host_apply).toBe('UNSUPPORTED')
    expect(result.plan).toBeUndefined()
    expect(result.errors.some(error => error.includes('Routing plan'))).toBe(true)
  })
})
