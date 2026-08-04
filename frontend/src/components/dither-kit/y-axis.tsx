"use client"

import { useChartPart } from "./chart-context"

export function YAxis({
  tickFormatter,
  tickCount = 4,
  tickMargin = 8,
  axis = "primary",
}: {
  tickFormatter?: (value: number) => string
  tickCount?: number
  tickMargin?: number
  axis?: "primary" | "secondary"
}) {
  const ctx = useChartPart("YAxis")
  if (!ctx.ready) return null
  const scale = axis === "secondary" ? ctx.ySecondary : ctx.y
  const secondary = axis === "secondary"

  return (
    <g className="fill-current font-mono text-[10px] text-muted-foreground">
      {scale.ticks(tickCount).map((t) => (
        <text
          key={t}
          x={secondary ? ctx.plot.width + tickMargin : -tickMargin}
          y={scale(t)}
          textAnchor={secondary ? "start" : "end"}
          dominantBaseline="central"
          fill="currentColor"
        >
          {tickFormatter ? tickFormatter(t) : t}
        </text>
      ))}
    </g>
  )
}
