// =============================================================================
// OtaFleetServer — Fleet Firmware Update Server  v1.0.0
// =============================================================================
//
// PURPOSE
//   Serves firmware .bin files to a fleet of deployed ESP32 devices so they can
//   update themselves over WiFi without a laptop.
//
// SPIFFS LAYOUT
//   /fw/NODE_A.bin          — firmware binary for device "NODE_A"
//   /fw/NODE_B.bin          — firmware binary for device "NODE_B"
//   /manifest.json          — version map: {"NODE_A":"1.0.1","NODE_B":"1.0.0"}
//
// HTTP ROUTES
//   GET  /                       redirect → /login  (or /dashboard if logged in)
//   GET  /login                  login form
//   POST /login                  authenticate, set session cookie
//   GET  /logout                 clear session, redirect → /login
//   GET  /dashboard              admin panel (auth required)
//   GET  /api/manifest           return /manifest.json  (NO auth — devices use this)
//   GET  /api/firmware/:device   stream /fw/:device.bin (NO auth — devices use this)
//   POST /api/upload/:device     accept multipart .bin upload (auth required)
//   GET  /api/files              list firmware files with sizes (auth required)
//   POST /api/delete/:device     delete a firmware file (auth required)
//
// ── HOW FLEET DEVICES SHOULD POLL FOR UPDATES ────────────────────────────────
//
//   // In your device firmware:
//
//   #include <HTTPClient.h>
//   #include <Update.h>
//   #include <ArduinoJson.h>
//
//   const char* OTA_SERVER_HOST = "http://192.168.x.x"; // this server's IP
//   const char* MY_DEVICE_NAME  = "NODE_A";             // this device's identity
//   const char* MY_VERSION      = "1.0.0";              // current firmware version
//
//   void checkForUpdate() {
//       HTTPClient http;
//       http.begin(String(OTA_SERVER_HOST) + "/api/manifest");
//       int code = http.GET();
//       if (code != 200) { http.end(); return; }
//
//       JsonDocument doc;
//       deserializeJson(doc, http.getString());
//       http.end();
//
//       const char* latest = doc[MY_DEVICE_NAME];
//       if (!latest || strcmp(latest, MY_VERSION) == 0) return; // already current
//
//       Serial.printf("[OTA] New firmware: %s → %s\n", MY_VERSION, latest);
//
//       http.begin(String(OTA_SERVER_HOST) + "/api/firmware/" + MY_DEVICE_NAME);
//       int fwCode = http.GET();
//       if (fwCode != 200) { http.end(); return; }
//
//       int totalLen = http.getSize();
//       WiFiClient* stream = http.getStreamPtr();
//
//       if (!Update.begin(totalLen)) { http.end(); return; }
//       size_t written = Update.writeStream(*stream);
//       http.end();
//
//       if (written == (size_t)totalLen && Update.end()) {
//           Serial.println("[OTA] Update OK — restarting");
//           ESP.restart();
//       } else {
//           Update.printError(Serial);
//       }
//   }
//
//   Call checkForUpdate() from loop() on a timer, e.g. every 60 seconds.
// =============================================================================

#include <Arduino.h>
#include <WiFi.h>
#include <SPIFFS.h>
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>
#include <esp_random.h>
#include <mbedtls/md.h>
#include "config.h"
#include "tls_cert.h"

// =============================================================================
// Session management
// =============================================================================

struct Session {
    String   token;
    uint32_t expires; // millis()
};

static const int MAX_SESSIONS = 4;
static Session   sessions[MAX_SESSIONS];

// Generate a 32-hex-char token from two 32-bit random words.
static String generateToken() {
    char buf[33];
    snprintf(buf, sizeof(buf), "%08X%08X%08X%08X",
             (unsigned)esp_random(), (unsigned)esp_random(),
             (unsigned)esp_random(), (unsigned)esp_random());
    return String(buf);
}

// Create (or renew) a session, return the token.
static String createSession() {
    uint32_t now = millis();
    // Try to find an expired slot to reuse
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].token.isEmpty() || (int32_t)(now - sessions[i].expires) >= 0) {
            sessions[i].token   = generateToken();
            sessions[i].expires = now + SESSION_TIMEOUT_MS;
            return sessions[i].token;
        }
    }
    // All slots full — evict the oldest (smallest expires value)
    int oldest = 0;
    for (int i = 1; i < MAX_SESSIONS; i++) {
        if ((int32_t)(sessions[i].expires - sessions[oldest].expires) < 0) {
            oldest = i;
        }
    }
    sessions[oldest].token   = generateToken();
    sessions[oldest].expires = now + SESSION_TIMEOUT_MS;
    return sessions[oldest].token;
}

// Invalidate a session by token.
static void destroySession(const String& token) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].token == token) {
            sessions[i].token   = "";
            sessions[i].expires = 0;
        }
    }
}

// Return a pointer to a valid, non-expired session, or nullptr.
static Session* getSession(AsyncWebServerRequest* request) {
    // Cookie header format: "key=value; key2=value2"
    if (!request->hasHeader("Cookie")) return nullptr;
    String cookies = request->header("Cookie");

    int idx = cookies.indexOf("session=");
    if (idx < 0) return nullptr;
    idx += 8; // skip "session="
    int end = cookies.indexOf(';', idx);
    String token = (end < 0) ? cookies.substring(idx) : cookies.substring(idx, end);
    token.trim();
    if (token.isEmpty()) return nullptr;

    uint32_t now = millis();
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].token == token) {
            if ((int32_t)(now - sessions[i].expires) >= 0) {
                // Expired
                sessions[i].token   = "";
                sessions[i].expires = 0;
                return nullptr;
            }
            // Refresh on activity
            sessions[i].expires = now + SESSION_TIMEOUT_MS;
            return &sessions[i];
        }
    }
    return nullptr;
}

// Convenience: is this request authenticated?
static bool isAuthenticated(AsyncWebServerRequest* request) {
    return getSession(request) != nullptr;
}

// =============================================================================
// SPIFFS helpers
// =============================================================================

static const char* MANIFEST_PATH = "/manifest.json";
static const char* FW_DIR        = "/fw";

// Read the manifest from SPIFFS and parse into a JsonDocument.
// Caller owns the document.  Returns false on failure.
static bool readManifest(JsonDocument& doc) {
    if (!SPIFFS.exists(MANIFEST_PATH)) {
        doc.to<JsonObject>(); // empty object
        return true;
    }
    File f = SPIFFS.open(MANIFEST_PATH, "r");
    if (!f) return false;
    DeserializationError err = deserializeJson(doc, f);
    f.close();
    return err == DeserializationError::Ok;
}

// Write a JsonDocument to the manifest file.
static bool writeManifest(JsonDocument& doc) {
    File f = SPIFFS.open(MANIFEST_PATH, "w");
    if (!f) return false;
    serializeJson(doc, f);
    f.close();
    return true;
}

// Ensure /fw directory exists (SPIFFS has no real dirs, but the path prefix works).
static void ensureFwDir() {
    // SPIFFS doesn't use real directories, but files with "/" in the name work fine.
    // Nothing to create — just a comment to clarify.
}

// Build the full SPIFFS path for a device firmware file.
static String fwPath(const String& device) {
    return String(FW_DIR) + "/" + device + ".bin";
}

// Validate a device name to prevent path traversal.
static bool validDeviceName(const String& name) {
    if (name.isEmpty() || name.length() > 32) return false;
    for (char c : name) {
        if (!isalnum(c) && c != '_' && c != '-') return false;
    }
    return true;
}

// =============================================================================
// Embedded HTML pages
// =============================================================================

static const char LOGIN_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OTA Fleet Server — Login</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',system-ui,sans-serif;
       display:flex;align-items:center;justify-content:center;min-height:100vh}
  .card{background:#161b22;border:1px solid #30363d;border-radius:10px;
        padding:40px 36px;width:100%;max-width:380px}
  h1{font-size:1.4rem;margin-bottom:6px;color:#58a6ff}
  .sub{font-size:.8rem;color:#8b949e;margin-bottom:28px}
  label{display:block;font-size:.85rem;color:#8b949e;margin-bottom:4px}
  input[type=text],input[type=password]{
        width:100%;padding:10px 12px;background:#0d1117;border:1px solid #30363d;
        border-radius:6px;color:#c9d1d9;font-size:.95rem;margin-bottom:16px;outline:none}
  input[type=text]:focus,input[type=password]:focus{border-color:#58a6ff}
  button{width:100%;padding:11px;background:#238636;border:none;border-radius:6px;
         color:#fff;font-size:1rem;cursor:pointer;font-weight:600;letter-spacing:.3px}
  button:hover{background:#2ea043}
  .err{background:#3d1f1f;border:1px solid #f85149;border-radius:6px;
       padding:10px 12px;font-size:.85rem;color:#f85149;margin-bottom:16px;display:none}
  .err.show{display:block}
  .badge{display:inline-block;background:#1f3a5f;color:#58a6ff;
         font-size:.7rem;padding:2px 8px;border-radius:20px;margin-bottom:20px}
</style>
</head>
<body>
<div class="card">
  <h1>OTA Fleet Server</h1>
  <span class="badge">DEVICE_ID_PLACEHOLDER &mdash; v1.0.0</span>
  <p class="sub">Sign in to manage firmware</p>
  <div class="err" id="err">ERR_MSG</div>
  <form method="POST" action="/login">
    <label for="u">Username</label>
    <input type="text" id="u" name="username" autocomplete="username" required>
    <label for="p">Password</label>
    <input type="password" id="p" name="password" autocomplete="current-password" required>
    <button type="submit">Sign in</button>
  </form>
</div>
<script>
  const err = document.getElementById('err');
  if (err.textContent.trim().length > 0) err.classList.add('show');
</script>
</body>
</html>
)rawliteral";

static const char DASHBOARD_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OTA Fleet Server — Dashboard</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh}
  header{background:#161b22;border-bottom:1px solid #30363d;
         padding:14px 24px;display:flex;align-items:center;justify-content:space-between}
  header h1{font-size:1.15rem;color:#58a6ff;font-weight:700}
  header .meta{font-size:.78rem;color:#8b949e}
  .logout{font-size:.82rem;color:#f85149;text-decoration:none;
          border:1px solid #f8514933;border-radius:5px;padding:4px 12px}
  .logout:hover{background:#3d1f1f}
  main{padding:28px 24px;max-width:960px;margin:0 auto}
  section{margin-bottom:36px}
  h2{font-size:1rem;color:#8b949e;text-transform:uppercase;letter-spacing:.08em;
     margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #21262d}
  /* Manifest table */
  table{width:100%;border-collapse:collapse;font-size:.9rem}
  th{text-align:left;padding:8px 12px;background:#161b22;color:#8b949e;font-weight:600;font-size:.8rem}
  td{padding:9px 12px;border-bottom:1px solid #21262d}
  tr:last-child td{border-bottom:none}
  .version{color:#3fb950;font-family:monospace;font-size:.95rem}
  .size{color:#8b949e;font-size:.85rem;font-family:monospace}
  .no-file{color:#8b949e;font-style:italic;font-size:.85rem}
  /* Upload + delete row */
  .actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
  .upload-form{display:flex;gap:8px;align-items:center}
  input[type=file]{background:#0d1117;border:1px solid #30363d;border-radius:5px;
                   color:#c9d1d9;padding:4px 8px;font-size:.82rem;cursor:pointer}
  .btn{border:none;border-radius:5px;padding:6px 14px;font-size:.82rem;
       cursor:pointer;font-weight:600;letter-spacing:.2px}
  .btn-upload{background:#1f6feb;color:#fff}
  .btn-upload:hover{background:#388bfd}
  .btn-delete{background:#3d1f1f;color:#f85149;border:1px solid #f8514933}
  .btn-delete:hover{background:#5a2020}
  /* Toast */
  #toast{position:fixed;bottom:24px;right:24px;background:#161b22;border:1px solid #30363d;
         border-radius:8px;padding:12px 20px;font-size:.87rem;color:#c9d1d9;
         transform:translateY(80px);opacity:0;transition:all .3s;z-index:99}
  #toast.show{transform:translateY(0);opacity:1}
  #toast.ok{border-color:#238636;color:#3fb950}
  #toast.err{border-color:#f85149;color:#f85149}
  .spinner{display:none;width:14px;height:14px;border:2px solid #30363d;
            border-top-color:#58a6ff;border-radius:50%;animation:spin .7s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  .uploader{display:flex;gap:8px;align-items:center}
</style>
</head>
<body>
<header>
  <h1>OTA Fleet Server</h1>
  <span class="meta" id="statusLine">Loading…</span>
  <a href="/logout" class="logout">Sign out</a>
</header>
<main>

  <!-- Manifest / version table -->
  <section>
    <h2>Firmware Versions</h2>
    <table id="manifestTable">
      <thead><tr><th>Device</th><th>Version</th><th>File Size</th><th>Actions</th></tr></thead>
      <tbody id="manifestBody"><tr><td colspan="4" style="color:#8b949e;padding:12px">Loading…</td></tr></tbody>
    </table>
  </section>

  <!-- Add firmware for a new device -->
  <section>
    <h2>Upload Firmware</h2>
    <div class="uploader">
      <input type="text" id="newDevice" placeholder="Device name e.g. NODE_A"
             style="background:#0d1117;border:1px solid #30363d;border-radius:5px;
                    color:#c9d1d9;padding:6px 10px;font-size:.88rem;width:200px;outline:none">
      <input type="file" id="newFile" accept=".bin">
      <button class="btn btn-upload" onclick="uploadNew()">Upload</button>
      <div class="spinner" id="newSpinner"></div>
    </div>
  </section>

</main>

<div id="toast"></div>

<script>
const toast = document.getElementById('toast');
function showToast(msg, type='ok') {
  toast.textContent = msg;
  toast.className = 'show ' + type;
  setTimeout(() => { toast.className = ''; }, 3500);
}

async function loadData() {
  try {
    const [mRes, fRes] = await Promise.all([
      fetch('/api/manifest'),
      fetch('/api/files')
    ]);
    const manifest = await mRes.json();
    const files    = fRes.ok ? await fRes.json() : {};

    // Build set of known devices from both manifest and file list
    const devices = new Set([...Object.keys(manifest), ...(files.files || []).map(f => f.device)]);
    const filemap = {};
    if (files.files) files.files.forEach(f => { filemap[f.device] = f; });

    const tbody = document.getElementById('manifestBody');
    if (devices.size === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="color:#8b949e;padding:12px">No firmware files uploaded yet.</td></tr>';
      document.getElementById('statusLine').textContent = 'No devices';
      return;
    }

    let rows = '';
    for (const dev of [...devices].sort()) {
      const ver  = manifest[dev] || '—';
      const fi   = filemap[dev];
      const size = fi ? formatBytes(fi.size) : '<span class="no-file">no file</span>';
      rows += `<tr>
        <td><strong>${esc(dev)}</strong></td>
        <td><span class="version">${esc(ver)}</span></td>
        <td class="size">${size}</td>
        <td>
          <div class="actions">
            <div class="upload-form">
              <input type="file" id="file_${esc(dev)}" accept=".bin">
              <button class="btn btn-upload" onclick="uploadDevice('${esc(dev)}')">Update</button>
              <div class="spinner" id="spin_${esc(dev)}"></div>
            </div>
            <button class="btn btn-delete" onclick="deleteDevice('${esc(dev)}')">Delete</button>
          </div>
        </td>
      </tr>`;
    }
    tbody.innerHTML = rows;
    document.getElementById('statusLine').textContent = devices.size + ' device(s) registered';
  } catch(e) {
    console.error(e);
    showToast('Failed to load data', 'err');
  }
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function formatBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n/1024).toFixed(1) + ' KB';
  return (n/1048576).toFixed(2) + ' MB';
}

async function uploadDevice(device) {
  const input = document.getElementById('file_' + device);
  if (!input || !input.files[0]) { showToast('Select a .bin file first', 'err'); return; }
  await doUpload(device, input.files[0], 'spin_' + device);
  input.value = '';
}

async function uploadNew() {
  const device = document.getElementById('newDevice').value.trim().toUpperCase();
  const file   = document.getElementById('newFile').files[0];
  if (!device) { showToast('Enter a device name', 'err'); return; }
  if (!file)   { showToast('Select a .bin file', 'err'); return; }
  await doUpload(device, file, 'newSpinner');
  document.getElementById('newDevice').value = '';
  document.getElementById('newFile').value = '';
}

async function doUpload(device, file, spinnerId) {
  const spinner = document.getElementById(spinnerId);
  if (spinner) { spinner.style.display = 'inline-block'; }
  const fd = new FormData();
  fd.append('firmware', file);
  try {
    const res = await fetch('/api/upload/' + encodeURIComponent(device), { method:'POST', body: fd });
    const txt = await res.text();
    if (res.ok) {
      showToast('Uploaded ' + device + ' OK', 'ok');
      await loadData();
    } else {
      showToast('Upload failed: ' + txt, 'err');
    }
  } catch(e) {
    showToast('Upload error: ' + e.message, 'err');
  } finally {
    if (spinner) { spinner.style.display = 'none'; }
  }
}

async function deleteDevice(device) {
  if (!confirm('Delete firmware for ' + device + '?')) return;
  try {
    const res = await fetch('/api/delete/' + encodeURIComponent(device), { method:'POST' });
    const txt = await res.text();
    if (res.ok) {
      showToast('Deleted ' + device, 'ok');
      await loadData();
    } else {
      showToast('Delete failed: ' + txt, 'err');
    }
  } catch(e) {
    showToast('Delete error: ' + e.message, 'err');
  }
}

loadData();
</script>
</body>
</html>
)rawliteral";

// =============================================================================
// Global objects
// =============================================================================

AsyncWebServer server(443);

// =============================================================================
// Utility: send a simple JSON error response
// =============================================================================

static void sendError(AsyncWebServerRequest* request, int code, const char* msg) {
    request->send(code, "application/json",
                  String("{\"error\":\"") + msg + "\"}");
}

// =============================================================================
// Route: GET /
// =============================================================================

static void handleRoot(AsyncWebServerRequest* request) {
    if (isAuthenticated(request)) {
        request->redirect("/dashboard");
    } else {
        request->redirect("/login");
    }
}

// =============================================================================
// Route: GET /login
// =============================================================================

static void handleLoginGet(AsyncWebServerRequest* request) {
    // Build the page — inject device ID and clear any error text
    String page = FPSTR(LOGIN_HTML);
    page.replace("DEVICE_ID_PLACEHOLDER", DEVICE_ID);
    page.replace("ERR_MSG", "");
    request->send(200, "text/html", page);
}

// =============================================================================
// Route: POST /login
// =============================================================================

static void handleLoginPost(AsyncWebServerRequest* request) {
    String username, password;
    if (request->hasParam("username", true)) username = request->getParam("username", true)->value();
    if (request->hasParam("password", true)) password = request->getParam("password", true)->value();

    if (username == ADMIN_USER && password == ADMIN_PASS) {
        String token = createSession();
        Serial.printf("[AUTH] Login OK for user '%s'\n", username.c_str());

        AsyncWebServerResponse* resp = request->beginResponse(302, "text/plain", "");
        resp->addHeader("Location", "/dashboard");
        // HttpOnly + SameSite=Strict for basic security
        resp->addHeader("Set-Cookie",
            "session=" + token + "; Path=/; HttpOnly; SameSite=Strict");
        request->send(resp);
    } else {
        Serial.printf("[AUTH] Login FAILED for user '%s'\n", username.c_str());
        String page = FPSTR(LOGIN_HTML);
        page.replace("DEVICE_ID_PLACEHOLDER", DEVICE_ID);
        page.replace("ERR_MSG", "Invalid username or password");
        request->send(401, "text/html", page);
    }
}

// =============================================================================
// Route: GET /logout
// =============================================================================

static void handleLogout(AsyncWebServerRequest* request) {
    if (request->hasHeader("Cookie")) {
        String cookies = request->header("Cookie");
        int idx = cookies.indexOf("session=");
        if (idx >= 0) {
            idx += 8;
            int end = cookies.indexOf(';', idx);
            String token = (end < 0) ? cookies.substring(idx) : cookies.substring(idx, end);
            token.trim();
            destroySession(token);
            Serial.println("[AUTH] User logged out");
        }
    }
    AsyncWebServerResponse* resp = request->beginResponse(302, "text/plain", "");
    resp->addHeader("Location", "/login");
    resp->addHeader("Set-Cookie", "session=; Path=/; Max-Age=0");
    request->send(resp);
}

// =============================================================================
// Route: GET /dashboard
// =============================================================================

static void handleDashboard(AsyncWebServerRequest* request) {
    if (!isAuthenticated(request)) {
        request->redirect("/login");
        return;
    }
    request->send(200, "text/html", FPSTR(DASHBOARD_HTML));
}

// =============================================================================
// Route: GET /api/manifest  (no auth — polled by fleet devices)
// =============================================================================

static void handleApiManifest(AsyncWebServerRequest* request) {
    if (!SPIFFS.exists(MANIFEST_PATH)) {
        // Return empty manifest rather than a 404
        request->send(200, "application/json", "{}");
        return;
    }
    File f = SPIFFS.open(MANIFEST_PATH, "r");
    if (!f) {
        sendError(request, 500, "Cannot open manifest");
        return;
    }
    // Stream file contents
    AsyncWebServerResponse* resp =
        request->beginResponse(SPIFFS, MANIFEST_PATH, "application/json");
    request->send(resp);
    Serial.println("[API] Manifest served");
}

// =============================================================================
// Route: GET /api/firmware/:device  (no auth — polled by fleet devices)
// =============================================================================

static void handleApiFirmware(AsyncWebServerRequest* request) {
    String device = request->pathArg(0);
    if (!validDeviceName(device)) {
        sendError(request, 400, "Invalid device name");
        return;
    }
    String path = fwPath(device);
    if (!SPIFFS.exists(path)) {
        sendError(request, 404, "Firmware not found");
        return;
    }
    Serial.printf("[DOWNLOAD] Serving firmware for '%s'\n", device.c_str());
    AsyncWebServerResponse* resp =
        request->beginResponse(SPIFFS, path, "application/octet-stream");
    resp->addHeader("Content-Disposition",
                    "attachment; filename=\"" + device + ".bin\"");
    // Include the firmware HMAC so devices can verify before flashing
    JsonDocument mdoc;
    if (readManifest(mdoc)) {
        String hmacKey = device + "_hmac";
        const char* hmac = mdoc[hmacKey] | "";
        if (strlen(hmac) == 64) {
            resp->addHeader("X-Firmware-HMAC", hmac);
        }
    }
    request->send(resp);
}

// =============================================================================
// Route: GET /api/files  (auth required)
// =============================================================================

static void handleApiFiles(AsyncWebServerRequest* request) {
    if (!isAuthenticated(request)) {
        sendError(request, 401, "Unauthorized");
        return;
    }

    JsonDocument doc;
    JsonArray arr = doc["files"].to<JsonArray>();

    File root = SPIFFS.open(FW_DIR);
    if (root && root.isDirectory()) {
        File entry = root.openNextFile();
        while (entry) {
            if (!entry.isDirectory()) {
                String name = String(entry.name()); // e.g. "NODE_A.bin"
                // Strip directory prefix if present
                int slash = name.lastIndexOf('/');
                if (slash >= 0) name = name.substring(slash + 1);
                // Strip .bin
                String device = name.endsWith(".bin")
                                ? name.substring(0, name.length() - 4)
                                : name;
                JsonObject obj = arr.add<JsonObject>();
                obj["device"] = device;
                obj["file"]   = name;
                obj["size"]   = (unsigned long)entry.size();
            }
            entry = root.openNextFile();
        }
    }

    String out;
    serializeJson(doc, out);
    request->send(200, "application/json", out);
}

// =============================================================================
// Route: POST /api/upload/:device  (auth required, multipart)
// =============================================================================

// We use the body handler approach: collect the raw body bytes and save.
// For multipart we parse the file field manually — ESPAsyncWebServer provides
// the file upload callback via onFileUpload.

static void handleApiUploadBody(AsyncWebServerRequest* request,
                                const String& filename,
                                size_t index,
                                uint8_t* data,
                                size_t len,
                                bool final) {
    // Called for each chunk of the uploaded file.
    // We stash state in a static struct (single-upload-at-a-time assumption
    // is fine for an admin tool).
    static File                  uploadFile;
    static String                uploadDevice;
    static bool                  uploadOk;
    static size_t                uploadBytes;
    static mbedtls_md_context_t  uploadHmacCtx;
    static bool                  uploadHmacActive;

    if (index == 0) {
        // First chunk — open the file
        if (!isAuthenticated(request)) {
            uploadOk = false;
            return;
        }
        uploadDevice = request->pathArg(0);
        if (!validDeviceName(uploadDevice)) {
            Serial.printf("[UPLOAD] Invalid device name '%s'\n", uploadDevice.c_str());
            uploadOk = false;
            return;
        }
        String path = fwPath(uploadDevice);
        // Remove old file first to avoid SPIFFS fragmentation
        if (SPIFFS.exists(path)) SPIFFS.remove(path);
        uploadFile = SPIFFS.open(path, "w");
        if (!uploadFile) {
            Serial.printf("[UPLOAD] Cannot open '%s' for writing\n", path.c_str());
            uploadOk = false;
            return;
        }
        uploadOk    = true;
        uploadBytes = 0;
        // Start HMAC-SHA256 context for firmware signing
        mbedtls_md_init(&uploadHmacCtx);
        const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        if (mbedtls_md_setup(&uploadHmacCtx, md_info, 1) == 0 &&
            mbedtls_md_hmac_starts(&uploadHmacCtx,
                                   (const uint8_t*)OTA_HMAC_KEY,
                                   strlen(OTA_HMAC_KEY)) == 0) {
            uploadHmacActive = true;
        } else {
            uploadHmacActive = false;
            Serial.println("[UPLOAD] HMAC init failed — upload will proceed unsigned");
        }
        Serial.printf("[UPLOAD] Receiving firmware for '%s'\n", uploadDevice.c_str());
    }

    if (!uploadOk) return;

    if (len > 0) {
        size_t written = uploadFile.write(data, len);
        if (written != len) {
            Serial.println("[UPLOAD] Write error — aborting");
            uploadOk = false;
            uploadFile.close();
            if (uploadHmacActive) { mbedtls_md_free(&uploadHmacCtx); uploadHmacActive = false; }
            SPIFFS.remove(fwPath(uploadDevice));
            return;
        }
        if (uploadHmacActive) mbedtls_md_hmac_update(&uploadHmacCtx, data, len);
        uploadBytes += len;
    }

    if (final) {
        uploadFile.close();
        if (uploadOk) {
            Serial.printf("[UPLOAD] Done — '%s' %u bytes\n",
                          uploadDevice.c_str(), (unsigned)uploadBytes);

            // Finalise HMAC and store hex digest in manifest under "<device>_hmac"
            String hmacHex = "";
            if (uploadHmacActive) {
                uint8_t digest[32];
                mbedtls_md_hmac_finish(&uploadHmacCtx, digest);
                mbedtls_md_free(&uploadHmacCtx);
                uploadHmacActive = false;
                char hexbuf[65];
                for (int i = 0; i < 32; i++) snprintf(hexbuf + i * 2, 3, "%02x", digest[i]);
                hmacHex = String(hexbuf);
                Serial.printf("[UPLOAD] HMAC-SHA256: %s\n", hmacHex.c_str());
            }

            JsonDocument mdoc;
            readManifest(mdoc);
            JsonObject mobj = mdoc.as<JsonObject>();
            if (!mobj.containsKey(uploadDevice)) {
                mobj[uploadDevice] = "0.0.0";
            }
            if (hmacHex.length() == 64) {
                mobj[uploadDevice + "_hmac"] = hmacHex;
            }
            writeManifest(mdoc);
            Serial.printf("[MANIFEST] Updated '%s'\n", uploadDevice.c_str());
        } else {
            if (uploadHmacActive) { mbedtls_md_free(&uploadHmacCtx); uploadHmacActive = false; }
        }
    }
}

static void handleApiUpload(AsyncWebServerRequest* request) {
    if (!isAuthenticated(request)) {
        sendError(request, 401, "Unauthorized");
        return;
    }
    // Response is sent here after the upload handler has finished.
    String device = request->pathArg(0);
    if (!validDeviceName(device)) {
        sendError(request, 400, "Invalid device name");
        return;
    }
    String path = fwPath(device);
    if (SPIFFS.exists(path)) {
        request->send(200, "text/plain", "OK");
    } else {
        sendError(request, 500, "Upload failed or no file received");
    }
}

// =============================================================================
// Route: POST /api/delete/:device  (auth required)
// =============================================================================

static void handleApiDelete(AsyncWebServerRequest* request) {
    if (!isAuthenticated(request)) {
        sendError(request, 401, "Unauthorized");
        return;
    }
    String device = request->pathArg(0);
    if (!validDeviceName(device)) {
        sendError(request, 400, "Invalid device name");
        return;
    }
    String path = fwPath(device);
    if (!SPIFFS.exists(path)) {
        sendError(request, 404, "Firmware not found");
        return;
    }
    SPIFFS.remove(path);
    Serial.printf("[DELETE] Removed firmware for '%s'\n", device.c_str());

    // Remove from manifest
    JsonDocument mdoc;
    if (readManifest(mdoc)) {
        JsonObject mobj = mdoc.as<JsonObject>();
        mobj.remove(device);
        writeManifest(mdoc);
        Serial.printf("[MANIFEST] Removed '%s'\n", device.c_str());
    }
    request->send(200, "text/plain", "OK");
}

// =============================================================================
// WiFi setup — STA with AP fallback
// =============================================================================

static void setupWiFi() {
    Serial.println("[WIFI] Connecting to STA…");
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    // Wait up to 15 seconds
    uint32_t start = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) {
        delay(500);
        Serial.print('.');
    }
    Serial.println();

    if (WiFi.status() == WL_CONNECTED) {
        Serial.print("[WIFI] Connected! IP: ");
        Serial.println(WiFi.localIP());
    } else {
        Serial.println("[WIFI] STA failed — starting fallback AP");
        WiFi.mode(WIFI_AP);
        WiFi.softAP(FALLBACK_AP_SSID, FALLBACK_AP_PASS);
        Serial.print("[WIFI] AP IP: ");
        Serial.println(WiFi.softAPIP());
    }
}

// =============================================================================
// Route registration
// =============================================================================

static void registerRoutes() {
    // Redirect root
    server.on("/", HTTP_GET, handleRoot);

    // Login / logout
    server.on("/login",   HTTP_GET,  handleLoginGet);
    server.on("/login",   HTTP_POST, handleLoginPost);
    server.on("/logout",  HTTP_GET,  handleLogout);

    // Dashboard (auth required)
    server.on("/dashboard", HTTP_GET, handleDashboard);

    // API — no auth
    server.on("^\\/api\\/manifest$", HTTP_GET, handleApiManifest);
    server.on("^\\/api\\/firmware\\/([A-Za-z0-9_-]+)$", HTTP_GET, handleApiFirmware);

    // API — auth required, with file upload
    server.on("^\\/api\\/upload\\/([A-Za-z0-9_-]+)$",
              HTTP_POST,
              handleApiUpload,          // response handler (called after upload)
              handleApiUploadBody);     // file upload handler

    server.on("^\\/api\\/files$",                       HTTP_GET,  handleApiFiles);
    server.on("^\\/api\\/delete\\/([A-Za-z0-9_-]+)$",  HTTP_POST, handleApiDelete);

    // 404 catch-all
    server.onNotFound([](AsyncWebServerRequest* request) {
        request->send(404, "text/plain", "Not found");
    });
}

// =============================================================================
// setup / loop
// =============================================================================

void setup() {
    Serial.begin(115200);
    delay(200);
    Serial.println();
    Serial.println("======================================");
    Serial.println("  OtaFleetServer  " DEVICE_ID "  v" DEVICE_VERSION);
    Serial.println("======================================");

    // Mount SPIFFS
    if (!SPIFFS.begin(true)) {  // true = format on fail
        Serial.println("[SPIFFS] Mount FAILED");
        // Without SPIFFS we can't serve firmware — halt and wait for reflash
        while (true) { delay(1000); }
    }
    Serial.println("[SPIFFS] Mounted OK");

    // Print SPIFFS info
    Serial.printf("[SPIFFS] Total: %u bytes  Used: %u bytes\n",
                  SPIFFS.totalBytes(), SPIFFS.usedBytes());

    // Ensure manifest exists
    if (!SPIFFS.exists(MANIFEST_PATH)) {
        File f = SPIFFS.open(MANIFEST_PATH, "w");
        if (f) { f.print("{}"); f.close(); }
        Serial.println("[SPIFFS] Created empty manifest.json");
    }

    ensureFwDir(); // no-op on SPIFFS, documents intent

    // Initialise session array
    for (int i = 0; i < MAX_SESSIONS; i++) {
        sessions[i].token   = "";
        sessions[i].expires = 0;
    }

    // Connect WiFi
    setupWiFi();

    // Register HTTP routes and start server
    registerRoutes();
    server.beginSecure(SERVER_CERT_PEM, SERVER_KEY_PEM);
    Serial.println("[HTTPS] Server started on port 443");

    if (WiFi.status() == WL_CONNECTED) {
        Serial.printf("[HTTP] Dashboard: http://%s/dashboard\n",
                      WiFi.localIP().toString().c_str());
        Serial.printf("[HTTP] Manifest:  http://%s/api/manifest\n",
                      WiFi.localIP().toString().c_str());
    } else {
        Serial.printf("[HTTP] AP mode — Dashboard: http://%s/dashboard\n",
                      WiFi.softAPIP().toString().c_str());
    }
}

void loop() {
    // ESPAsyncWebServer runs entirely in callbacks — nothing to poll here.
    // Optionally print a heartbeat every 30 s for debugging.
    static uint32_t lastHeartbeat = 0;
    if (millis() - lastHeartbeat >= 30000) {
        lastHeartbeat = millis();
        if (WiFi.getMode() == WIFI_STA) {
            Serial.printf("[HEARTBEAT] IP=%s  SPIFFS used=%u/%u\n",
                          WiFi.localIP().toString().c_str(),
                          SPIFFS.usedBytes(), SPIFFS.totalBytes());
        } else {
            Serial.printf("[HEARTBEAT] AP mode  SPIFFS used=%u/%u\n",
                          SPIFFS.usedBytes(), SPIFFS.totalBytes());
        }
    }
}
