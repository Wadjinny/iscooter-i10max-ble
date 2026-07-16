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

## Usage

1. Open the site (or `frontend/index.html`) in Chrome or Edge — Web Bluetooth required.
2. Use HTTPS or `localhost` (BLE is not available on insecure origins).
3. Click **Connect** and pick your scooter.

Static HTML/CSS/JS under `frontend/` — no build step.

## Deploy

Push to `master` rsyncs `frontend/` over SSH and updates the Caddy site config.
