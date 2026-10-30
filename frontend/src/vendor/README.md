# shadcn stylesheet provenance

`shadcn-tailwind.css` is the unmodified `dist/tailwind.css` from the npm package
`shadcn@4.18.0` (MIT; full upstream notice in `shadcn-LICENSE.md`).
Upstream: https://github.com/shadcn-ui/ui/tree/shadcn%404.18.0/packages/shadcn
Source tarball: https://registry.npmjs.org/shadcn/-/shadcn-4.18.0.tgz
SHA-256: `bc7d83425702955b4cb67cb14ede9d603f9d912376d57a2d81d661094d2a782a`.

The application imports only this stylesheet from the shadcn package. Keeping
these exact static bytes locally avoids installing the unrelated scaffolding
CLI, MCP server and vulnerable deepmerge graph during application builds.
Components and registry configuration remain unchanged. To add components,
maintainers can invoke a separately reviewed CLI version explicitly; the
application itself does not require it at build or runtime. Never remove this
notice/license when updating the stylesheet. The regression test locks the
baseline bytes and import, so future visual changes require an explicit review.
