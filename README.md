# iScooter BLE Reverse Engineering (Web Bluetooth)

This project is an attempt to reverse engineer the protocol used by the **iScooter** Android application (package name: `com.iscootercar.iscooter`).

## Goals

- Emulate the authentication process.
- Emulate the command structure for the **i10max** scooter model.

## Technology

- Implemented entirely using the **Web Bluetooth API**.
- Runs 100% in the browser (client-side only).
- **No server** required.

## Usage

1. Open `index.html` in a browser that supports Web Bluetooth (e.g., Chrome, Edge).
2. Click "Connect" to scan for and connect to your scooter. 
