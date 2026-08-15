#pragma once

// =============================================================================
// OtaFleetServer — Configuration
// =============================================================================
// Change WIFI_SSID / WIFI_PASSWORD to match your network.
// Change ADMIN_USER / ADMIN_PASS before deploying on a real network.
// =============================================================================

// ── WiFi, credentials, and OTA signing key are in secrets.h (gitignored) ─────
// Copy include/secrets.example.h → include/secrets.h and fill in real values.
#include "secrets.h"

// Fallback soft-AP SSID (name is not sensitive — only the password is in secrets.h)
#define FALLBACK_AP_SSID "OtaFleetServer"

// ── Device identity ──────────────────────────────────────────────────────────
#define DEVICE_ID      "ota-fleet-server-01"
#define DEVICE_VERSION "1.0.0"

// ── Storage limits ───────────────────────────────────────────────────────────
#define MAX_FIRMWARE_FILES 8

// ── Session management ────────────────────────────────────────────────────────
// 30-minute idle timeout
#define SESSION_TIMEOUT_MS (30UL * 60UL * 1000UL)
