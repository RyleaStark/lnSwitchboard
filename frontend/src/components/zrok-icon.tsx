import type { SVGProps } from "react"

/** Compact zrok wordmark-inspired connector glyph. */
export function ZrokIcon({ className, ...props }: SVGProps<SVGSVGElement>) {
  return (
    <svg aria-hidden="true" className={className} viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg" {...props}>
      <rect width="48" height="48" rx="12" fill="#5B46F6" />
      <path d="M12 15h24v5L21 31h15v5H12v-5l15-11H12z" fill="white" />
    </svg>
  )
}
