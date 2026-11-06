import { describe, expect, it } from 'vitest'
import { bytes, deviceGroup, severity } from './format'
import type { Device } from './types'

describe('inventory presentation', () => {
  it('labels counters without inventing rates', () => {
    expect(bytes(1024)).toBe('1.0 KB')
    expect(bytes(-1)).toBe('—')
  })
  it('keeps VPN and virtual devices outside the physical group', () => {
    expect(deviceGroup({ kind: 'vpn' } as Device)).toBe('Virtual / VPN')
    expect(deviceGroup({ kind: 'wifi' } as Device)).toBe('Physical')
  })
  it('does not hide blocked findings behind informational ones', () => {
    expect(severity([{ code: 'nm', status: 'INFO', detail: '' }, { code: 'vpn', status: 'BLOCKED', detail: '' }])).toBe('BLOCKED')
  })
})
