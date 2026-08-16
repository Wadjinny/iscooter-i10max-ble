# iScooter i10 Max (Web Bluetooth)

Browser UI to connect to an **iScooter i10 Max** over BLE and reverse-engineer / control the protocol used by the official Android app (`com.iscootercar.iscooter`).

**Live:** [iscooter.w-ilyas.site](https://iscooter.w-ilyas.site)

## Goals

- Emulate authentication and the i10 Max command structure
- Read live telemetry and send control commands from the browser

## Features

- Scan and connect via the Web Bluetooth API
- Live speed, battery, mode, lock, and related status
- 100% client-side — no backend

## Run locally

Static HTML/CSS/JS under `frontend/` — no build step. Serve over `localhost` so Web Bluetooth is allowed:

```bash
python3 -m http.server -d frontend 8080
```

Then open http://localhost:8080 in Chrome or Edge.

1. Use HTTPS or `localhost` (BLE is not available on insecure origins).
2. Click **Connect** and pick your scooter.


## Deploy

Push to `master` rsyncs `frontend/` over SSH and updates the Caddy site config.
