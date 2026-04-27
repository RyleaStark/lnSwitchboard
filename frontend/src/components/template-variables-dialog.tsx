import type { ReactNode } from "react"
import { InfoIcon } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

const templateVariables = [
  {
    token: "{ln_address}",
    meaning: "Exact payer-facing address",
    example: "alice+vip@example.com",
    available: "Metadata and success",
  },
  {
    token: "{username}",
    meaning: "Requested local-part, including any +tag",
    example: "alice+vip",
    available: "Metadata and success",
  },
  {
    token: "{local_part}",
    meaning: "Base handle before any +tag",
    example: "alice",
    available: "Metadata and success",
  },
  {
    token: "{tag}",
    meaning: "Tag after the + sign; blank when no tag is used",
    example: "vip",
    available: "Metadata and success",
  },
  {
    token: "{domain}",
    meaning: "Domain serving the LNURL endpoint",
    example: "example.com",
    available: "Metadata and success",
  },
  {
    token: "{amount_sat}",
    meaning: "Requested amount in sats",
    example: "21",
    available: "Success only",
  },
  {
    token: "{amount_msat}",
    meaning: "Requested amount in millisats",
    example: "21000",
    available: "Success only",
  },
]

const variableRowGridClassName =
  "grid grid-cols-[minmax(8rem,0.75fr)_minmax(14rem,2fr)_minmax(10rem,1.25fr)] gap-x-4 gap-y-2"

export function TemplateVariablesDialog({ trigger }: { trigger?: ReactNode }) {
  return (
    <Dialog>
      <DialogTrigger asChild>
        {trigger ?? <Button type="button" variant="outline">
          <InfoIcon data-icon="inline-start" />
          Variables
        </Button>}
      </DialogTrigger>
      <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>Template variables</DialogTitle>
          <DialogDescription>
            Examples assume a payer requested alice+vip@example.com for 21 sats.
          </DialogDescription>
        </DialogHeader>
        <div className="overflow-x-auto rounded-md border">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead colSpan={3} className="h-auto p-0">
                  <div className={`${variableRowGridClassName} px-2 py-3`}>
                    <span>Variable</span>
                    <span>Expands to</span>
                    <span>Example</span>
                  </div>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {templateVariables.map((item) => (
                <TableRow key={item.token}>
                  <TableCell colSpan={3} className="p-0">
                    <div className={`${variableRowGridClassName} px-2 py-3`}>
                      <code className="font-mono">{item.token}</code>
                      <span>{item.meaning}</span>
                      <code className="font-mono">{item.example}</code>
                      <div className="col-span-3">
                        <Badge variant={item.available === "Success only" ? "secondary" : "outline"}>{item.available}</Badge>
                      </div>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </DialogContent>
    </Dialog>
  )
}
