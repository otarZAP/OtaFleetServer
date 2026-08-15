# OtaFleetServer — Over-the-Air Firmware Update Server

**Status:** Complete
**Board:** ESP32 dev board
**Role:** Self-hosted firmware distribution server with HMAC-SHA256 integrity verification

---

## What It Does

OtaFleetServer lets you update a fleet of ESP32 devices over WiFi without plugging in a laptop. You upload `.bin` files to it via a web dashboard; devices poll it periodically and self-update when a newer version is listed.

Firmware integrity is enforced via **HMAC-SHA256** — devices reject any firmware that is missing or fails the HMAC header check, preventing delivery of tampered binaries.

---

## Hardware

| Item | Notes |
|---|---|
| ESP32 dev board | Any standard 38-pin ESP32 |
| (no OLED required) | Status is available via serial monitor |

---

## SPIFFS Layout

```
/fw/NODE_A.bin         — firmware binary for device "NODE_A"
/fw/NODE_B.bin         — firmware binary for device "NODE_B"
/manifest.json         — version map: {"NODE_A":"1.0.1","NODE_B":"1.0.0",...}
```

Device names are arbitrary — whatever identity string a given firmware reports as `MY_DEVICE_NAME`.

---

## HTTP API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/` | — | Redirect to login/dashboard |
| GET/POST | `/login` | — | Admin login |
| GET | `/logout` | session | Clear session |
| GET | `/dashboard` | session | Admin panel — upload/delete firmware |
| GET | `/api/manifest` | none | Version map (polled by fleet devices) |
| GET | `/api/firmware/:device` | none | Stream `.bin` with `X-Firmware-HMAC` header |
| POST | `/api/upload/:device` | session | Upload new `.bin` via multipart |
| GET | `/api/files` | session | List stored firmware with sizes |
| POST | `/api/delete/:device` | session | Delete a firmware file |

The manifest and firmware endpoints are **unauthenticated by design** — fleet devices poll them without credentials. Admin routes (upload/delete/dashboard) require session login.

---

## Configuration

Copy `include/secrets.example.h` → `include/secrets.h` and fill in:

```cpp
#define WIFI_SSID        "your-wifi"
#define WIFI_PASSWORD    "password"
#define ADMIN_USER       "admin"
#define ADMIN_PASSWORD   "your-password"
#define OTA_HMAC_KEY     "your-hmac-key"   // must match OTA_HMAC_KEY on every fleet device
```

Copy `include/tls_cert.example.h` → `include/tls_cert.h` and generate your own self-signed cert:

```bash
openssl req -x509 -newkey rsa:2048 \
  -keyout key.pem -out cert.pem -days 3650 -nodes -subj "/CN=OtaFleetServer"
```

---

## Flash

```bash
cd OtaFleetServer
pio run -t upload         # flash firmware
pio run -t uploadfs       # upload SPIFFS (needed if you have pre-built .bin files to include)
pio device monitor        # 115200 baud
```

After boot, check serial for the assigned IP. Browse to `https://<IP>/` to access the admin dashboard.

---

## How Fleet Devices Poll for Updates

Fleet devices call OtaFleetServer on a timer (typically hourly):

1. `GET /api/manifest` — compare `MY_DEVICE_NAME` version against `DEVICE_VERSION`
2. If newer: `GET /api/firmware/MY_DEVICE_NAME` — download binary
3. Verify `X-Firmware-HMAC` header (HMAC-SHA256 of the binary using the shared key)
4. If HMAC valid: flash and reboot. If missing or invalid: reject and stay on current firmware.

A minimal client-side implementation is documented at the top of `src/main.cpp`.

---

## Notes for Reviewers

This is a portfolio-scoped extraction of a larger personal fleet-management project. `MAX_SESSIONS` is small (4) and sessions live in RAM — appropriate for a single-admin local tool, not a multi-tenant service. The upload handler assumes one upload in flight at a time via a static struct, which is fine for an admin-only tool but wouldn't hold up under concurrent uploads.
