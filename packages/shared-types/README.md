# shared-types

* `design-tokens.json` — colours, gradients, radii and fonts shared by the website (Tailwind theme in `globals.css`) and the WPF client (`Themes/Theme.xaml`).
* API contract — the single source of truth is the zod schemas in `apps/website/src/lib/validation.ts`. The C# client mirrors them in `apps/desktop/src/Screensharing.Desktop/Services/Payloads.cs`, and the integrity-manifest algorithm is implemented identically in `apps/website/src/lib/manifest.ts` and `apps/desktop/src/Screensharing.Scanner/Reporting/Manifest.cs` (a shared reference vector is asserted in both test suites).
