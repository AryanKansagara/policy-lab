// The matrix's "Filter by port" text. Only a whole decimal number from 0 to 65535 is a filter;
// anything else the user typed is reported instead of being treated as "no filter".
export type PortFilter = { kind: 'any' } | { kind: 'port'; port: number } | { kind: 'invalid'; message: string }

export const PORT_FILTER_ERROR = 'Port must be a number from 0 to 65535.'

export function parsePortFilter(text: string): PortFilter {
  const t = text.trim()
  if (!t) return { kind: 'any' }
  if (!/^\d+$/.test(t)) return { kind: 'invalid', message: PORT_FILTER_ERROR }
  const port = Number(t)
  return port > 65535 ? { kind: 'invalid', message: PORT_FILTER_ERROR } : { kind: 'port', port }
}
