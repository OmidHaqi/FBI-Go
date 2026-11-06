import type { Device, Finding } from './types'

export function bytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let number = value
  let index = 0
  while (number >= 1024 && index < units.length - 1) { number /= 1024; index++ }
  return `${number.toFixed(index === 0 ? 0 : 1)} ${units[index]}`
}

export function deviceGroup(device: Device): 'Physical' | 'Virtual / VPN' {
  return device.kind === 'vpn' || device.kind === 'virtual' || device.kind === 'bridge' || device.kind === 'loopback' ? 'Virtual / VPN' : 'Physical'
}

export function severity(findings: Finding[]): 'BLOCKED' | 'WARNING' | 'UNKNOWN' | 'INFO' {
  if (findings.some(f => f.status === 'BLOCKED')) return 'BLOCKED'
  if (findings.some(f => f.status === 'WARNING')) return 'WARNING'
  if (findings.some(f => f.status === 'UNKNOWN')) return 'UNKNOWN'
  return 'INFO'
}
