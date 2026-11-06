import { invoke } from '@tauri-apps/api/core'
import { useEffect, useState } from 'react'
import { demoMode } from './bridge'

export interface TrafficSample {
  name: string
  rx_bytes: number
  tx_bytes: number
  rx_bytes_per_second: number | null
  tx_bytes_per_second: number | null
}

export function speed(value: number | null | undefined): string {
  if (value == null) return 'Initializing'
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)} MB/s`
  if (value >= 1_000) return `${(value / 1_000).toFixed(0)} KB/s`
  return `${value} B/s`
}

export function useTraffic(): Map<string, TrafficSample> {
  const [samples, setSamples] = useState<TrafficSample[]>([])
  useEffect(() => {
    if (demoMode) return
    let active = true
    const update = () => { void invoke<TrafficSample[]>('traffic_snapshot').then(value => { if (active) setSamples(value) }).catch(() => { if (active) setSamples([]) }) }
    update()
    const timer = window.setInterval(update, 1000)
    return () => { active = false; window.clearInterval(timer) }
  }, [])
  return new Map(samples.map(sample => [sample.name, sample]))
}
