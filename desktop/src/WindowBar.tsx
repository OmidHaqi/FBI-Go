import { isTauri } from '@tauri-apps/api/core'
import { getCurrentWindow } from '@tauri-apps/api/window'
import { Maximize2, Minus, Square, X } from 'lucide-react'
import logo from '../src-tauri/icons/icon.svg'

export default function WindowBar() {
  const native = isTauri()
  const appWindow = native ? getCurrentWindow() : null
  function drag(event: React.MouseEvent) {
    if (event.button !== 0 || !appWindow) return
    if (event.detail === 2) void appWindow.toggleMaximize()
    else void appWindow.startDragging()
  }
  return <div className="window-bar">
    <div className="window-drag" onMouseDown={drag} aria-label="FBI-Go window title">
      <img src={logo} alt="" /><strong>FBI-Go</strong><span>Network manager</span>
    </div>
    {appWindow && <div className="window-controls">
      <button aria-label="Minimize window" title="Minimize" onClick={() => void appWindow.minimize()}><Minus size={16} /></button>
      <button aria-label="Maximize or restore window" title="Maximize or restore" onClick={() => void appWindow.toggleMaximize()}><Square size={13} /><Maximize2 size={13} className="sr-only" /></button>
      <button aria-label="Close window" title="Close" onClick={() => void appWindow.close()}><X size={16} /></button>
    </div>}
  </div>
}
