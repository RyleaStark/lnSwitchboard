import type { SVGProps } from "react"

import { cn } from "@/lib/utils"

export function CloudflareIcon({ className, ...props }: SVGProps<SVGSVGElement>) {
  return (
    <svg
      viewBox="0 0 24 24"
      aria-hidden="true"
      className={cn("size-4", className)}
      {...props}
    >
      <path
        fill="#f38020"
        d="M9.5 8.2a5 5 0 0 1 9.3 1.7 3.9 3.9 0 0 1-.6 7.8H7.5a4.1 4.1 0 0 1-.6-8.2 5 5 0 0 1 2.6-1.3Z"
      />
      <path
        fill="#faae40"
        d="M15.6 8.9a4.7 4.7 0 0 1 4.4 3.1 3 3 0 0 1-.7 5.8h-7.7a3.4 3.4 0 0 1-.3-6.8 4.8 4.8 0 0 1 4.3-2.1Z"
      />
      <path
        fill="#ffffff"
        d="M6.9 17.6h12.5a2.4 2.4 0 0 0 1.7-.7 3.1 3.1 0 0 1-1.8.5H7.5a3 3 0 0 1-2.2-.9 4 4 0 0 0 1.6 1.1Z"
        opacity="0.85"
      />
    </svg>
  )
}
