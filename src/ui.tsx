import { useEffect, useState, type MouseEvent, type ReactNode } from 'react'
import { applyThemeMode, readThemeMode, type ThemeMode } from './themeMode.ts'

export function usePath() {
  const [path, setPath] = useState(() => location.pathname)
  useEffect(() => {
    const on = () => setPath(location.pathname)
    addEventListener('popstate', on)
    return () => removeEventListener('popstate', on)
  }, [])
  return path
}
export function go(href: string) {
  history.pushState({}, '', href)
  dispatchEvent(new PopStateEvent('popstate'))
  scrollTo(0, 0)
}
export function Link({ href, className, children }: { href: string; className?: string; children: ReactNode }) {
  const onClick = (e: MouseEvent) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return
    e.preventDefault()
    go(href)
  }
  return <a href={href} className={className} onClick={onClick}>{children}</a>
}
export function Brand() {
  return (
    <Link href="/" className="brand">
      <span className="monogram" aria-hidden="true">PL</span>
      <span>Policy Lab</span>
    </Link>
  )
}
export function ThemeToggle() {
  const [mode, setMode] = useState<ThemeMode>(readThemeMode)
  const next = mode === 'dark' ? 'light' : 'dark'
  return (
    <button type="button" className="btn ghost icon" aria-label={`Switch to ${next} mode`} title={`Switch to ${next} mode`} onClick={() => { applyThemeMode(next); setMode(next) }}>
      <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
        {mode === 'dark'
          ? <><circle cx="8" cy="8" r="3.2" fill="currentColor" /><path d="M8 1v2M8 13v2M1 8h2M13 8h2M3 3l1.4 1.4M11.6 11.6 13 13M3 13l1.4-1.4M11.6 4.4 13 3" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" /></>
          : <path d="M13.5 9.8A6 6 0 0 1 6.2 2.5a6 6 0 1 0 7.3 7.3Z" fill="currentColor" />}
      </svg>
    </button>
  )
}
export function Footer() {
  return (
    <footer className="footer">
      <span>Built by Aryan Kansagara. Independent project, not affiliated with Tailscale.</span>
    </footer>
  )
}
