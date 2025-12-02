# api/index.py
# Flask app designed to run in Vercel serverless using vercel-wsgi
# Endpoints:
#  - POST /api/captcha/create   -> create challenge (HMAC-signed)
#  - GET  /api/captcha          -> serve swipe HTML (clean preview)
#  - POST /api/captcha/verify   -> verify swipe payload (server checks)
#  - GET  /                       -> health

from flask import Flask, request, jsonify, Response
import time, uuid, hmac, hashlib, base64, json
from vercel_wsgi import vercel_wsgi

app = Flask(__name__)

# ----- Configuration -----
# Replace with env var in production (Vercel env variables)
SECRET_KEY = b"replace_this_with_a_real_secret"  # bytes

# In-memory store for extra metadata (optional)
# Note: Serverless instances are ephemeral — use Redis for production multi-instance
challenges = {}  # { challenge_id: { "created": ts_sec, "min_drag": int, "secret": str } }

# ----- Helpers -----
def sign_challenge(challenge_id: str, ts: int) -> str:
    msg = f"{challenge_id}|{ts}".encode()
    return hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()

def verify_signature(challenge_id: str, ts: int, signature: str) -> bool:
    expected = sign_challenge(challenge_id, ts)
    return hmac.compare_digest(expected, signature)

# ----- API: create challenge -----
@app.route("/api/captcha/create", methods=["POST"])
def api_create():
    cid = str(uuid.uuid4())
    ts = int(time.time())
    sig = sign_challenge(cid, ts)

    # optional server-side values
    challenges[cid] = {
        "created": ts,
        "min_drag": 230,
        "secret": base64.b64encode(uuid.uuid4().bytes).decode()  # random server secret
    }

    return jsonify({
        "challenge_id": cid,
        "timestamp": ts,
        "signature": sig,
        "expires_in": 120
    })

# ----- UI: serve swipe page (clean, not obfuscated) -----
@app.route("/api/captcha", methods=["GET"])
def serve_captcha():
    # If caller supplies ?challenge_id=... we preserve it, otherwise server will create one on load
    # (frontend will call /api/captcha/create automatically to get challenge)
    html = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Swipe Captcha</title>
<style>
  body{display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f5f7fb;font-family:Inter,system-ui,Arial;}
  .card{width:340px;background:#fff;padding:20px;border-radius:14px;box-shadow:0 6px 20px rgba(0,0,0,0.08);text-align:center;}
  .swipe-area{width:100%;height:56px;border-radius:28px;background:#eef4ff;position:relative;overflow:hidden;margin-top:12px;}
  .indicator{position:absolute;left:0;top:0;height:100%;width:0;background:linear-gradient(90deg,#7ecbff,#3aa0ff);border-radius:28px;transition:width 0.04s linear;z-index:0}
  .handle{width:56px;height:56px;border-radius:50%;position:absolute;left:0;top:0;z-index:5;background:#2463f3;color:white;display:flex;align-items:center;justify-content:center;font-size:20px;box-shadow:0 8px 20px rgba(36,99,243,0.24);user-select:none;touch-action:none;}
  #status{margin-top:14px;min-height:20px;font-size:14px}
  .muted{color:#6b7280;font-size:13px;margin-top:8px}
</style>
</head>
<body>
  <div class="card">
    <h3 style="margin:0">Geser untuk verifikasi</h3>
    <p class="muted">Tarik ikon panah ke kanan</p>

    <div class="swipe-area" id="swipeArea" aria-label="Swipe area">
      <div class="indicator" id="indicator"></div>
      <div class="handle" id="handle" role="button" aria-label="drag handle">
        <!-- your arrow SVG -->
        <svg width="30" height="30" viewBox="0 0 24 24" fill="none"
         stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <polyline points="9 18 15 12 9 6"></polyline>
        </svg>
      </div>
    </div>

    <div id="status"></div>
    <div class="muted" id="meta"></div>
  </div>

<script>
(async function(){
  const handle = document.getElementById('handle');
  const area = document.getElementById('swipeArea');
  const indicator = document.getElementById('indicator');
  const status = document.getElementById('status');
  const meta = document.getElementById('meta');

  // Fetch challenge from backend
  let CHAL = null;
  try {
    const res = await fetch('/api/captcha/create', { method: 'POST' });
    CHAL = await res.json();
    meta.textContent = 'Challenge: ' + CHAL.challenge_id;
  } catch(e){
    meta.textContent = 'Gagal membuat challenge';
    console.error(e);
    return;
  }

  let dragging = false;
  let startClientX = 0;
  let offsetX = 0;

  // compute max dynamically (on resize too)
  function getMax() {
    const rect = area.getBoundingClientRect();
    const hrect = handle.getBoundingClientRect();
    return rect.width - hrect.width;
  }

  handle.addEventListener('pointerdown', function(e){
    e.preventDefault();
    dragging = true;
    startClientX = e.clientX || (e.touches && e.touches[0].clientX) || 0;
    const rect = handle.getBoundingClientRect();
    offsetX = startClientX - rect.left;
    status.textContent = '';
    // capture pointer for better behavior
    if (e.pointerId) handle.setPointerCapture(e.pointerId);
    // track points for optional advanced verification (not sent now)
    window._swipePoints = [{t: Date.now(), x: Math.round(rect.left)}];
  });

  window.addEventListener('pointermove', function(e){
    if (!dragging) return;
    const clientX = e.clientX || (e.touches && e.touches[0].clientX) || 0;
    const areaRect = area.getBoundingClientRect();
    const max = getMax();
    let x = clientX - areaRect.left - offsetX;
    if (x < 0) x = 0;
    if (x > max) x = max;
    handle.style.left = x + 'px';
    indicator.style.width = ((x / max) * 100) + '%';
    // record
    window._swipePoints.push({t: Date.now(), x: Math.round(x)});
  });

  window.addEventListener('pointerup', async function(e){
    if (!dragging) return;
    dragging = false;
    const max = getMax();
    const finalLeft = parseInt(handle.style.left || '0', 10);
    // if near end -> verify
    if (finalLeft >= max - 6){
      status.style.color = 'gray';
      status.textContent = 'Memverifikasi...';

      // minimal proof to server (we use HMAC signature on server side)
      try {
        const payload = {
          challenge_id: CHAL.challenge_id,
          timestamp: CHAL.timestamp,
          signature: CHAL.signature,
          // optional: send some proof (here base64 of "swiped-<id>")
          proof: btoa('swiped-' + CHAL.challenge_id),
          // optionally send some raw points for server-side advanced checks:
          points: window._swipePoints || []
        };
        const r = await fetch('/api/captcha/verify', {
          method: 'POST',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify(payload)
        });
        const j = await r.json();
        if (j && j.success){
          status.style.color = 'green';
          status.textContent = '✔ Berhasil diverifikasi';
        } else {
          status.style.color = 'red';
          status.textContent = '✘ Verifikasi gagal: ' + (j.error || j.status || 'unknown');
          // reset UI
          handle.style.left = '0px';
          indicator.style.width = '0%';
        }
      } catch(err){
        status.style.color = 'red';
        status.textContent = '✘ Error jaringan';
        handle.style.left = '0px';
        indicator.style.width = '0%';
      }
    } else {
      // not far enough -> reset
      status.style.color = 'red';
      status.textContent = '✘ Swipe kurang jauh';
      handle.style.left = '0px';
      indicator.style.width = '0%';
    }
  });

  // responsive: recompute max on resize to avoid stuck position
  window.addEventListener('resize', function(){
    // reset to avoid stuck layout
    handle.style.left = '0px';
    indicator.style.width = '0%';
  });
})();
</script>
</body>
</html>
"""
    return Response(html, mimetype="text/html")

# ----- Verify endpoint -----
@app.route("/api/captcha/verify", methods=["POST"])
def api_verify():
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"success": False, "error": "bad_request"}), 400

    challenge_id = data.get("challenge_id")
    timestamp = data.get("timestamp")
    signature = data.get("signature")
    proof = data.get("proof", "")
    points = data.get("points", [])

    # basic param check
    if not (challenge_id and timestamp and signature):
        return jsonify({"success": False, "error": "missing_params"}), 400

    # signature check and expiration
    now = int(time.time())
    try:
        ts = int(timestamp)
    except:
        return jsonify({"success": False, "error": "bad_timestamp"}), 400

    if now - ts > 120:
        return jsonify({"success": False, "error": "expired"}), 400

    if not verify_signature(challenge_id, ts, signature):
        return jsonify({"success": False, "error": "invalid_signature"}), 403

    # minimal proof check (frontend sends base64 "swiped-<id>")
    expected_proof = base64.b64encode(f"swiped-{challenge_id}".encode()).decode()
    if proof != expected_proof:
        return jsonify({"success": False, "error": "invalid_proof"}), 400

    # OPTIONAL: deeper checks using 'points' (timestamps & x positions)
    # If points present, run simple heuristics
    if isinstance(points, list) and len(points) > 0:
        # ensure increasing timestamps and position progression
        try:
            times = [int(p['t']) if isinstance(p, dict) else int(p[0]) for p in points]
            xs = [int(p['x']) if isinstance(p, dict) else int(p[1]) for p in points]
        except Exception:
            return jsonify({"success": False, "error": "malformed_points"}), 400

        # monotonic times
        for i in range(1, len(times)):
            if times[i] <= times[i-1]:
                return jsonify({"success": False, "error": "bad_timing"}), 400

        total_ms = times[-1] - times[0]
        if total_ms < 60:
            return jsonify({"success": False, "error": "too_fast"}), 400
        if total_ms > 10000:
            return jsonify({"success": False, "error": "too_slow"}), 400

        # final position must be near end (use min_drag from store if present)
        meta = challenges.get(challenge_id)
        min_drag = meta.get('min_drag') if meta else 230
        final_x = xs[-1]
        if final_x < min_drag:
            return jsonify({"success": False, "error": "incomplete"}), 400

    # success: produce final token (HMAC of id + server secret) and optionally delete challenge
    final_token = hmac.new(SECRET_KEY, f"{challenge_id}".encode(), hashlib.sha256).hexdigest()
    # delete stored meta to avoid replay
    challenges.pop(challenge_id, None)

    return jsonify({"success": True, "token": final_token})


# Health root for sanity
@app.route("/", methods=["GET"])
def root_health():
    return jsonify({"status": "ok", "server_time": int(time.time())})

# Vercel entrypoint: handler(event, context)
def handler(event, context):
    return vercel_wsgi(app, event, context)

# For local dev: allow running via "python api/index.py"
if __name__ == "__main__":
    app.run(debug=True, port=5000)
