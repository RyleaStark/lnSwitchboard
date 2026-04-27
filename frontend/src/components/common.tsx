import { CopyIcon, FileQuestionIcon } from "lucide-react"
import { toast } from "sonner"

import { Button } from "@/components/ui/button"
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Skeleton } from "@/components/ui/skeleton"
import { copyText, formatTimestamp } from "@/lib/format"
import { cn } from "@/lib/utils"

export function PageHeader({
  eyebrow,
  title,
  description,
  action,
  actionAlign = "end",
}: {
  eyebrow: string
  title: string
  description: string
  action?: React.ReactNode
  actionAlign?: "start" | "end"
}) {
  return (
    <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
      <div className="flex max-w-3xl flex-col gap-2">
        <p className="text-xs font-medium uppercase tracking-normal text-muted-foreground">{eyebrow}</p>
        <h1 className="text-3xl font-semibold tracking-normal text-foreground md:text-4xl">{title}</h1>
        <p className="text-sm leading-6 text-muted-foreground">{description}</p>
      </div>
      {action ? <div className={cn("flex shrink-0 items-center gap-2", actionAlign === "start" && "md:self-start")}>{action}</div> : null}
    </div>
  )
}

export function LoadingRows({ rows = 4 }: { rows?: number }) {
  return (
    <div className="flex flex-col gap-3">
      {Array.from({ length: rows }).map((_, index) => (
        <Skeleton key={index} className="h-16 w-full rounded-md" />
      ))}
    </div>
  )
}

export function EmptyPanel({
  title,
  description,
}: {
  title: string
  description: string
}) {
  return (
    <Empty className="border border-dashed bg-muted/20">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <FileQuestionIcon />
        </EmptyMedia>
        <EmptyTitle>{title}</EmptyTitle>
        <EmptyDescription>{description}</EmptyDescription>
      </EmptyHeader>
      <EmptyContent />
    </Empty>
  )
}

export function Timestamp({ value, fallback = "-" }: { value?: string | null; fallback?: string }) {
  const formatted = formatTimestamp(value)
  if (!formatted) return <span>{fallback}</span>
  return <time title={`${formatted.iso} UTC`}>{formatted.display}</time>
}

export function CopyButton({
  value,
  label = "Copy",
  copiedLabel = "Copied",
  className,
}: {
  value?: string | null
  label?: string
  copiedLabel?: string
  className?: string
}) {
  return (
    <Button
      type="button"
      variant="ghost"
      size="sm"
      className={cn("shrink-0", className)}
      disabled={!value}
      onClick={async () => {
        if (!value) return
        await copyText(value)
        toast.success(copiedLabel)
      }}
    >
      <CopyIcon data-icon="inline-start" />
      {label}
    </Button>
  )
}

export function CodeBlock({
  children,
  className,
}: {
  children: React.ReactNode
  className?: string
}) {
  return (
    <pre className={cn("max-h-80 w-full max-w-full min-w-0 overflow-auto rounded-md border bg-muted/40 p-3 text-left text-xs text-foreground", className)}>
      <code className="block min-w-max font-mono">{children}</code>
    </pre>
  )
}

export function PageError({ message }: { message: string }) {
  return (
    <div className="rounded-md border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive">
      {message}
    </div>
  )
}
