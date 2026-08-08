---
name: "RiseVPN Control"
description: "A precise route observatory for calm, legible VPN control."
colors:
  signal-cobalt: "#2f63ff"
  signal-cobalt-high: "#6790ff"
  verified-green: "#48ca86"
  caution-amber: "#e6ac58"
  fault-red: "#e45d55"
  instrument-ink: "#edf1f5"
  secondary-ink: "#9ca8b7"
  graphite-black: "#090d12"
  deep-recess: "#0d131a"
  steel-surface: "#121a24"
  raised-steel: "#18222e"
  structural-line: "#344150"
typography:
  display:
    fontFamily: "Roboto Condensed Variable, Arial Narrow, sans-serif"
    fontSize: "clamp(3.625rem, 6vw, 6.25rem)"
    fontWeight: 600
    lineHeight: 0.88
    letterSpacing: "-0.025em"
  headline:
    fontFamily: "Roboto Condensed Variable, Arial Narrow, sans-serif"
    fontSize: "clamp(3rem, 5vw, 4.875rem)"
    fontWeight: 600
    lineHeight: 0.93
    letterSpacing: "-0.025em"
  title:
    fontFamily: "Roboto Condensed Variable, Arial Narrow, sans-serif"
    fontSize: "2.5rem"
    fontWeight: 600
    lineHeight: 1
  body:
    fontFamily: "Manrope, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.75
  label:
    fontFamily: "Roboto Condensed Variable, Arial Narrow, sans-serif"
    fontSize: "0.6875rem"
    fontWeight: 600
    lineHeight: 1
    letterSpacing: "0.14em"
rounded:
  square: "0px"
  status-dot: "50%"
spacing:
  micro: "5px"
  compact: "8px"
  control: "12px"
  field: "18px"
  panel: "28px"
  section: "110px"
components:
  button-primary:
    backgroundColor: "{colors.signal-cobalt}"
    textColor: "#ffffff"
    typography: "{typography.body}"
    rounded: "{rounded.square}"
    padding: "0 26px"
    height: "64px"
  button-primary-hover:
    backgroundColor: "#3e70ff"
    textColor: "#ffffff"
  button-secondary:
    backgroundColor: "#162139"
    textColor: "#ffffff"
    rounded: "{rounded.square}"
    padding: "10px 14px"
  input-secure:
    backgroundColor: "{colors.deep-recess}"
    textColor: "#ffffff"
    typography: "{typography.title}"
    rounded: "{rounded.square}"
    padding: "0 18px"
    height: "58px"
  panel-operational:
    backgroundColor: "#101720"
    textColor: "{colors.instrument-ink}"
    rounded: "{rounded.square}"
    padding: "{spacing.panel}"
  status-verified:
    backgroundColor: "#0c1d16"
    textColor: "{colors.verified-green}"
    typography: "{typography.label}"
    rounded: "{rounded.square}"
    padding: "0 20px"
    height: "44px"
---

# Design System: RiseVPN Control

## Overview

**Creative North Star: "The Route Observatory"**

RiseVPN looks and behaves like a calibrated network instrument: dark, exact, and visibly built to measure before it acts. Graphite recesses, steel panels, etched dividers, gridded readouts, and clipped corners make the infrastructure tangible without drifting into decorative “cybersecurity” neon.

The public surface uses this world in Persuade mode, with oversized compressed headlines and the route instrument as product proof. Cabinet and administration surfaces shift into Operate mode: denser grids, quieter hierarchy, and status-first panels retain the same material and signal language. The system is Russian-first and treats live state, limits, and warnings as evidence rather than spectacle.

**Key Characteristics:**

- Instrument-like graphite and steel surfaces with fine structural lines.
- Condensed, uppercase display type paired with calm, readable body copy.
- Cobalt marks selection and action; green marks verified state; amber and red carry operational meaning.
- Clipped industrial corners, layered bezels, measurement grids, screws, scales, and tabular readouts.
- Expressive Persuade layouts and compact Operate layouts share one token vocabulary.
- Responsive reflow, visible keyboard focus, reduced-motion support, and no horizontal overflow are baseline behavior.

## Colors

The palette is a dark instrument chassis animated by sparse, high-meaning signal colors.

### Primary

- **Signal Cobalt:** The sole action and selected-path color. Use for primary actions, active measurements, usage progress, and high-value links.
- **Signal Cobalt High:** A lighter companion reserved for focus outlines, small labels, active navigation text, and readable links on dark steel.

### Secondary

- **Verified Green:** Communicates healthy, ready, compliant, or successfully bound states. Pair it with text or an icon so status never depends on color alone.

### Tertiary

- **Caution Amber:** Marks pending, degraded, Grace, or attention-needed conditions without panic.
- **Fault Red:** Marks offline, critical, destructive, and error states.

### Neutral

- **Instrument Ink:** Primary text and high-contrast readings.
- **Secondary Ink:** Explanatory copy, metadata, and non-critical labels.
- **Graphite Black:** The page canvas and deepest chassis surface.
- **Deep Recess:** Inset rails, input wells, and recessed readout zones.
- **Steel Surface:** Standard interactive and marketing surface.
- **Raised Steel:** Selected navigation and elevated tonal layers.
- **Structural Line:** Panel edges, grid rules, separators, and table structure.

### Named Rules

**The Signal Discipline Rule.** Cobalt means action or selection, green means verified health, amber means attention, and red means fault; never use these colors as interchangeable decoration.

**The Dark Instrument Rule.** New surfaces begin with graphite and steel layering. Do not introduce light cards, pastel fills, or unrelated accent hues.

## Typography

**Display Font:** Roboto Condensed Variable (with Arial Narrow and sans-serif fallbacks)
**Body Font:** Manrope (with sans-serif fallback)

**Character:** Roboto Condensed makes Russian headlines and readings feel engineered, compact, and authoritative. Manrope keeps explanations humane and legible, preventing the instrument aesthetic from becoming cold or cryptic.

### Hierarchy

- **Display** (600, fluid oversized scale, 0.88 line-height): Hero statements, full-page state titles, and legal-page titles; uppercase and tightly set.
- **Headline** (600, fluid section scale, 0.93 line-height): Major section introductions; uppercase with compact leading.
- **Title** (600, 2.5rem, 1 line-height): Panel outcomes, plan names, route results, and key operational states.
- **Body** (400, 1rem, 1.75 line-height): Explanations and marketing copy; keep important paragraphs near 52–75 characters per line.
- **Label** (600, 0.6875rem, 0.14em tracking): Instrument captions, workspace eyebrows, state labels, and compact metadata; uppercase.

### Named Rules

**The Readout Rule.** Use condensed type for commands, measurements, and hierarchy; use Manrope for sentences users must understand.

**The Uppercase Boundary Rule.** Uppercase belongs to display headings and instrument labels, not paragraphs, form help, warnings, or FAQ answers.

## Layout

The marketing layout alternates wide split fields with full-width rails and four-column measurement tables. Major sections use generous vertical padding (typically 90–120px) and 4–5vw horizontal gutters. The product workspace uses a 245px sticky rail, a fluid content area, 20px grid gaps, and 28px panel interiors. Compact data rows are separated by lines instead of floating cards.

At 1100px, dense four- and five-column structures reduce to two or three columns, while primary dashboard content becomes single-column. At 760px, marketing splits stack, section gutters become 20px, the header hides secondary navigation, and the workspace rail becomes a fixed 66px bottom navigation. Instrument detail is selectively removed rather than uniformly shrunk. Every grid child must permit shrinking, long content must wrap or ellipsize deliberately, and the viewport must remain free of horizontal overflow.

**The Wide-to-Stack Rule.** Preserve hierarchy as columns collapse: headline before evidence, state before explanation, and primary action before secondary metadata.

**The Cabinet Density Rule.** Operate surfaces use 20px gaps and line-separated rows; do not import the landing page’s oversized whitespace into routine administration.

## Elevation & Depth

Depth is structural, not glossy. Most surfaces separate through tonal steps and one-pixel steel borders. The signature route instrument adds a deep ambient shadow, inset bezel rings, a metal texture, and a restrained cobalt route glow; routine cards remain flat within the chassis.

### Shadow Vocabulary

- **Instrument Drop** (`0 28px 65px #000a`): Grounds the route instrument as the one materially elevated object.
- **Instrument Bezel** (`inset 0 0 0 7px #080c11, inset 0 0 0 9px #344150`): Builds the multilayer equipment casing.
- **Action Signal** (`0 14px 34px #102c8866`): A restrained cobalt field under the primary action only.

### Named Rules

**The Structural Depth Rule.** Use borders, recesses, texture, and nested frames before shadows; reserve obvious elevation for the route instrument and primary action.

## Shapes

The system is rectilinear and mechanically clipped. Standard panels and controls use a shared 12px diagonal corner cut rather than rounded rectangles. The hero instrument uses larger opposing 16px cuts and nested rectangular bezels. Circular geometry is reserved for screws, route nodes, status dots, and pulses—small functional parts inside an angular chassis.

Borders are fine and low-contrast by default, becoming brighter only where a component is selected, verified, focused, or warning. Dashed strokes and grid lines belong to measurement paths and calibration, not general decoration.

**The Cut-Corner Rule.** Reuse the established diagonal cut for actionable controls and framed panels; do not substitute soft pill shapes or arbitrary radius scales.

## Components

### Buttons

- **Shape:** Angular control with opposing 12px clipped corners and no radius.
- **Primary:** Signal Cobalt fill, white label, 64px minimum height, generous horizontal padding, and a directional icon when forwarding the journey.
- **Hover / Focus:** Hover brightens to the high cobalt range and rises 2px; active presses down 1px. Keyboard focus uses a 2px Signal Cobalt High outline with 4px offset.
- **Secondary / Ghost:** Raised Steel fill with a steel border for local cabinet actions. Text links retain a cobalt-high tint and avoid button chrome.

### Chips

- **Style:** Status markers are compact readouts rather than pills: recessed dark fill, semantic border, uppercase condensed text, and an icon or explicit label.
- **State:** Green is verified, amber is pending/degraded, and red is critical/offline. Never show a bare color dot without adjacent state text in consequential contexts.

### Cards / Containers

- **Corner Style:** Square geometry with the shared 12px clipped-corner silhouette.
- **Background:** Dark steel tonal layers over Graphite Black; signature panels may add the existing metal texture.
- **Shadow Strategy:** Flat by default; use structural borders and nested framing. Follow the Elevation & Depth rules for the route instrument.
- **Border:** One-pixel Structural Line or a nearby brighter steel value when emphasis is required.
- **Internal Padding:** 28px for primary cabinet panels, 20px for compact metrics, and 34px/25px for plan cells.

### Inputs / Fields

- **Style:** A 58px recessed graphite field with a one-pixel steel border and 18px horizontal padding. Secure numeric input uses large condensed figures with deliberate tracking.
- **Focus:** The global 2px cobalt-high outline remains visible outside the field; border changes may support it but never replace it.
- **Error / Disabled:** Errors use explicit Fault Red text; disabled actions retain their shape and reduce opacity without disappearing.

### Navigation

Public navigation is centered, sparse, and secondary to the brand and login action. Cabinet navigation is a vertical 245px rail; active items use Raised Steel, brighter text, an icon, and the cut-corner silhouette. At mobile width it becomes a fixed bottom bar with icon-over-label items and hides the redundant brand/help chrome.

The RiseVPN wordmark is always rendered as a single lockup: “Rise” in Instrument Ink and “VPN” in Signal Cobalt. Once a session is detected, the public header replaces “Войти” with “Кабинет”; it never shows both actions.

### Customer language

Public copy uses plain Russian and describes the action a customer takes: sign in, create a device, copy the subscription, and add it to v2RayTun. Internal protocol terms, quota implementation, provisioning, and compliance mechanics stay out of the marketing journey. Automatic location selection is explained only by the hero instrument and the dedicated cabinet panel.

### Account consent

The first authenticated visit is intercepted by a focused agreement gate. It has one checkbox, a visible link to the complete agreement, and one disabled-until-accepted action. Consent is persisted by the control server before device and subscription APIs become available.

### Device manager

The device page is a line-separated operational list rather than a card gallery. Every device has a clear state and a “Получить ссылку” action. The subscription URL remains visible in a read-only field after retrieval, so clipboard denial never strands the user. Subscription tokens are stored encrypted; legacy devices receive a new token on first retrieval.

### Help chooser

Help opens a dedicated three-option surface: FAQ for self-service, email for ordinary questions, and Telegram for paid priority support. Each option names the destination and consequence before navigation.

### Public footer

The footer contains the white/cobalt wordmark, operator name, INN, year, a restrained encryption statement, and one legal destination: the agreement. It does not repeat secondary navigation or internal compliance terminology.

### Route Instrument

The signature proof component is a clipped steel enclosure with layered bezels, screws, vents, scales, a measurement grid, dashed candidate paths, one solid cobalt selected path, and a green verified endpoint. Its labels use condensed technical typography and tabular readings. On mobile, preserve the route story and verification result while removing secondary stability and result readouts that would crowd the display.

### Operational Warning

Warnings are full-width, line-bordered bands with an icon, a concise bold state, and plain-language consequence. Amber communicates pending or Grace; red communicates critical failure. The copy must stay calm, specific, and actionable.

## Do's and Don'ts

### Do:

- **Do** make real network state, route selection, quota, and operational status the visual evidence.
- **Do** use cobalt sparingly for selection and action, and pair every semantic status color with readable text or an icon.
- **Do** preserve the shared graphite/steel chassis, clipped corners, one-pixel rules, and condensed readout typography across Persuade and Operate surfaces.
- **Do** recompose at 1100px and 760px, keep focus visible, honor reduced motion, and verify there is no horizontal overflow.
- **Do** localize Russian labels, dates, bytes, speeds, durations, and ruble values consistently.

### Don't:

- **Don't** turn the system into generic neon cyberpunk, glassmorphism, or a collection of floating rounded cards.
- **Don't** use green, amber, or red decoratively or allow status to depend on color alone.
- **Don't** add manual location selectors: every plan uses automatic location selection.
- **Don't** compress the route instrument until its measurements become illegible; remove secondary detail at narrow widths.
- **Don't** fabricate performance, network, legal, adoption, or uptime claims to fill a composition.
