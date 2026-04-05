# SentinelBench Dashboard

React dashboard — coming in v0.2.

## Planned views

| View | Description |
|------|-------------|
| ATT&CK Heatmap | Colour-encodes detection latency per technique (green → amber → red) |
| Run History | Per-technique table: result, latency (s), severity match, date |
| Remediation Panel | Missed detections only — generated KQL with copy button |

## Tech stack

- React 18
- D3.js (heatmap rendering)
- Vite (dev server + build)

## Running (once built)

```bash
cd dashboard
npm install
npm run dev
```
