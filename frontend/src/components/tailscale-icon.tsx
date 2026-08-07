import type { SVGProps } from "react"

/** Official Tailscale brand mark, based on https://tailscale.com/favicon.svg. */
export function TailscaleIcon({ className, ...props }: SVGProps<SVGSVGElement>) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      viewBox="0 0 48 48"
      xmlns="http://www.w3.org/2000/svg"
      {...props}
    >
      <path
        fill="#1f1e1e"
        d="M28.8 0C35.5206 0 38.881 0 41.4479 1.30792C43.7058 2.4584 45.5416 4.29417 46.6921 6.55211C48 9.11905 48 12.4794 48 19.2V28.8C48 35.5206 48 38.881 46.6921 41.4479C45.5416 43.7058 43.7058 45.5416 41.4479 46.6921C38.881 48 35.5206 48 28.8 48H19.2C12.4794 48 9.11905 48 6.55211 46.6921C4.29417 45.5416 2.4584 4.29417 1.30792 6.55211C0 9.11905 0 12.4794 0 19.2V28.8C0 35.5206 0 38.881 1.30792 41.4479C2.4584 43.7058 4.29417 45.5416 6.55211 46.6921C9.11905 48 12.4794 48 19.2 48H28.8Z"
      />
      <g fill="#fff">
        <circle cx="15" cy="24" r="3" />
        <circle cx="24" cy="24" r="3" />
        <circle cx="33" cy="24" r="3" />
        <circle cx="24" cy="33" r="3" />
      </g>
      <g fill="#fff" opacity="0.4">
        <circle cx="15" cy="15" r="3" />
        <circle cx="24" cy="15" r="3" />
        <circle cx="33" cy="15" r="3" />
        <circle cx="15" cy="33" r="3" />
        <circle cx="33" cy="33" r="3" />
      </g>
    </svg>
  )
}
