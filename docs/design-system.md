# PRAHARI Console — design system

Token-based, no utility framework. Every value lives in
`frontend/src/styles/tokens.css`; components consume roles, never raw hex.

## Why dark-first

The primary context is an operations console, frequently on a dim screen beside a
map. Light mode is a **selected** set of steps validated against the light
surface, not an inverted copy of the dark one.

Both modes are stamped on `document.documentElement.dataset.theme` and persisted,
with the stored value applied by an inline script before first paint so the
console never flashes the wrong surface.

## Layers

| File | Contains |
|---|---|
| `styles/tokens.css` | colour, type, space, radius, elevation, motion |
| `styles/base.css` | reset, element defaults, focus treatment, scrollbars |
| `styles/components.css` | named component classes |

Helpers are explicitly enumerated (`.muted`, `.mono`, `.truncate`, `.row`,
`.stack`); there is no open-ended utility vocabulary. This is deliberate — the
previous prototype used Tailwind class names without Tailwind installed, so every
one of those classes silently did nothing.

## Surfaces

| Role | Dark | Light |
|---|---|---|
| Page | `#0b0f12` | `#f2f4f3` |
| Surface | `#0f1418` | `#f7f8f7` |
| Raised | `#151c21` | `#ffffff` |
| Sunken | `#080b0e` | `#eaedec` |

`--accent` (`#35d0b8` dark / `#0a8f7d` light) is reserved for interaction and
identity. **It never encodes data** — otherwise a button and a chart series would
claim the same meaning.

## Chart series

Six categorical hues, in a fixed order. **The order is the colour-vision-deficiency
safety mechanism, not a cosmetic choice** — do not shuffle or substitute without
re-running the validator.

| Slot | Hue | Dark | Light |
|---|---|---|---|
| 1 | blue | `#3987e5` | `#2a78d6` |
| 2 | orange | `#d95926` | `#eb6834` |
| 3 | aqua | `#199e70` | `#1baf7a` |
| 4 | yellow | `#c98500` | `#eda100` |
| 5 | magenta | `#d55181` | `#e87ba4` |
| 6 | green | `#008300` | `#008300` |

Validated against this project's own surfaces:

```
dark  (surface #0f1418) — ALL CHECKS PASS
  lightness band   all 6 inside L 0.48–0.67
  chroma floor     all 6 >= 0.1
  CVD separation   worst adjacent #c98500↔#199e70  ΔE 8.4 (protan)
  normal vision    worst adjacent #d55181↔#c98500  ΔE 19.3
  contrast         all 6 >= 3:1

light (surface #f7f8f7) — ALL CHECKS PASS
  CVD separation   worst adjacent #eda100↔#1baf7a  ΔE 9.1 (protan)
  normal vision    worst adjacent #e87ba4↔#eda100  ΔE 19.6
  contrast         WARN: aqua/yellow/magenta below 3:1 → relief required
```

The light-mode contrast warning is discharged by the **relief rule**: every chart
direct-labels its latest value and ships a `<details>` table view, so no value is
reachable only by reading a colour off the plot.

## Status colours

`--good` `#0ca30c` · `--warning` `#fab219` · `--serious` `#ec835a` ·
`--critical` `#d03b3b`

Reserved. Never reused as a seventh series. Every status badge renders a **glyph
and a text label** alongside the colour, so meaning survives greyscale, CVD and
`forced-colors`.

## Chart rules

- **One axis per chart.** Altitude, groundspeed and battery are different scales,
  so they are small multiples — never a dual-axis plot, where a crossing point
  would read as meaningful when it is an artefact of two arbitrary scales.
- Single series per chart, so the title carries identity and no legend box is
  needed.
- 2px lines, 4px latest-value marker ringed in the surface colour, recessive
  gridlines, crosshair + tooltip on hover.
- `font-variant-numeric: tabular-nums` on every telemetry value, so digits do not
  jitter as they change.

## Track display

`components/TacticalMap.jsx` deliberately draws **no external map tiles**. A
ground control station is routinely operated on an isolated network, where a tile
CDN would both fail and leak the operating area to a third party. Positions are
projected to a local east/north plane in metres around the first fix, which is
accurate well past the range of a single sortie.

## Accessibility

- One focus treatment (`:focus-visible`, 2px accent ring) everywhere.
- Skip link to `#main`.
- Status never carried by colour alone.
- `prefers-reduced-motion` drops transition durations to zero and stops the
  realtime pulse.
- Charts expose an `aria-label` with the latest value, plus a table view.

## Re-validating after a palette change

```bash
node scripts/validate_palette.js "<hex,hex,…>" --mode dark  --surface "#0f1418"
node scripts/validate_palette.js "<hex,hex,…>" --mode light --surface "#f7f8f7"
```

Run it on candidate orderings and choose only among the passing ones.
