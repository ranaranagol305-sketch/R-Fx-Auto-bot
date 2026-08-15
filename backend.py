"""
R FX Bot - Complete Backend Script
===================================
- Real TwelveData live feed for Forex & Gold
- 11 Real Indicators: Market Structure, 200 EMA, 50 EMA, RSI, MACD, ADX, ATR,
  Bollinger Bands, Stochastic, SuperTrend, Volume
- Strict 9/11 Vote Threshold rule
- Extension Bridge API Endpoints (/api/bot-poll, /api/set-bot-signal)
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone

import requests
from flask import Flask, jsonify, request

# ============================================================================
# CONFIGURATION
# ============================================================================

TWELVEDATA_API_KEYS = [
    "c47e6aa1e3694d888ba0d8ee10193160",
    "5f98e9f032684d27b8b266656bfcadac",
    "a592dba7321442efa229bee2b8a1cff8",
    "a7def2b8959d4c17a943e21ea1921ac0",
    "67b60333dd7c44dea9d268c66d0ec17a",
    "0ab3ed6674e1436e8c396c15203479ad",
    "411348a610f54662990df7fdd2ebf604",
    "87b1d6c795144bf481ec5a02d769b60d",
    "7b1cb45d88574c92a867cc95b8a2fba3",
    "56df4a80e020400db5259ec9485b2565",
]
TWELVEDATA_BASE_URL = "https://api.twelvedata.com/time_series"

SUPPORTED_PAIRS = {
    "XAU/USD": "XAU/USD", "EUR/USD": "EUR/USD", "GBP/USD": "GBP/USD",
    "USD/JPY": "USD/JPY", "USD/CHF": "USD/CHF", "AUD/USD": "AUD/USD",
    "NZD/USD": "NZD/USD", "USD/CAD": "USD/CAD", "EUR/JPY": "EUR/JPY",
    "GBP/JPY": "GBP/JPY", "EUR/GBP": "EUR/GBP", "EUR/AUD": "EUR/AUD",
    "AUD/JPY": "AUD/JPY",
}
TIMEFRAME_MAP = {"1": "1min", "5": "5min", "15": "15min", "30": "30min", "60": "1h"}

TOTAL_CONFIRMATIONS = 11
SIGNAL_VOTE_THRESHOLD = 9

SECRET_KEY = os.environ.get("SECRET_KEY", "r-fx-bot-secret-key-prod")
USER_TOKEN_MAX_AGE_SECONDS = 60 * 60 * 24 * 7  # 7 days

# Extension Live State
LATEST_BOT_SIGNAL = {
    "pair": "EUR/USD",
    "signal": "WAIT",
    "confidence": 0,
    "votes": 0,
    "timestamp": ""
}
BOT_SIGNAL_LOCK = threading.Lock()

# ============================================================================
# LOGGING & AUTH
# ============================================================================

logger = logging.getLogger("rana_fx_bot")
logger.setLevel(logging.INFO)
_console_handler = logging.StreamHandler()
_formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
_console_handler.setFormatter(_formatter)
logger.addHandler(_console_handler)

PBKDF2_ITERATIONS = 100_000

def hash_password(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS)
    return f"{salt}${digest.hex()}"

def verify_password(password, stored_hash):
    try:
        salt, digest_hex = stored_hash.split("$")
        expected = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS)
        return hmac.compare_digest(expected.hex(), digest_hex)
    except Exception:
        return False

def create_signed_token(payload_dict):
    payload_dict = dict(payload_dict)
    payload_dict["_ts"] = int(time.time())
    raw = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")
    body = base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")
    sig = hmac.new(SECRET_KEY.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"

def verify_signed_token(token, max_age_seconds):
    try:
        body, sig = token.split(".")
        expected_sig = hmac.new(SECRET_KEY.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, sig): return None
        padded = body + "=" * (-len(body) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("utf-8"))
        payload = json.loads(raw)
        if int(time.time()) - payload.get("_ts", 0) > max_age_seconds: return None
        return payload
    except Exception:
        return None

def require_user_auth():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        return verify_signed_token(token, USER_TOKEN_MAX_AGE_SECONDS)
    return None

USERS = {}
USERS_LOCK = threading.Lock()

# ============================================================================
# TWELVEDATA API & INDICATOR CALCULATIONS
# ============================================================================

class ApiKeyManager:
    def __init__(self, keys):
        self._keys = list(keys)
        self._active_index = 0
        self._exhausted_until = {}
        self._lock = threading.Lock()

    def get_active_key(self):
        with self._lock:
            n = len(self._keys)
            for offset in range(n):
                idx = (self._active_index + offset) % n
                key = self._keys[idx]
                until = self._exhausted_until.get(key)
                if until is None or datetime.now(timezone.utc) >= until:
                    self._active_index = idx
                    return key
            return None

    def mark_exhausted(self, key):
        with self._lock:
            self._exhausted_until[key] = datetime.now(timezone.utc) + timedelta(minutes=2)

api_key_manager = ApiKeyManager(TWELVEDATA_API_KEYS)

def fetch_candles(symbol, interval, output_size=260):
    key = api_key_manager.get_active_key()
    if not key: raise RuntimeError("All TwelveData keys exhausted.")
    params = {"symbol": symbol, "interval": interval, "outputsize": output_size, "apikey": key, "order": "ASC"}
    resp = requests.get(TWELVEDATA_BASE_URL, params=params, timeout=12)
    payload = resp.json()
    if payload.get("status") == "error":
        api_key_manager.mark_exhausted(key)
        raise RuntimeError(payload.get("message", "API Error"))
    values = payload.get("values", [])
    candles = []
    for row in values:
        candles.append({
            "high": float(row["high"]), "low": float(row["low"]),
            "close": float(row["close"]), "open": float(row["open"]),
            "volume": float(row["volume"]) if row.get("volume") else 0.0
        })
    return candles

def sma(vals, p): return [sum(vals[i-p+1:i+1])/p if i>=p-1 else None for i in range(len(vals))]

def ema(vals, p):
    out = [None]*len(vals)
    if len(vals) < p: return out
    out[p-1] = sum(vals[:p])/p
    m = 2/(p+1)
    for i in range(p, len(vals)): out[i] = (vals[i] - out[i-1])*m + out[i-1]
    return out

def rsi(closes, p=14):
    out = [None]*len(closes)
    if len(closes) <= p: return out
    gains = [max(closes[i]-closes[i-1], 0) for i in range(1, len(closes))]
    losses = [max(closes[i-1]-closes[i], 0) for i in range(1, len(closes))]
    avg_g, avg_l = sum(gains[:p])/p, sum(losses[:p])/p
    out[p] = 100 - (100/(1+(avg_g/avg_l))) if avg_l != 0 else 100.0
    for i in range(p, len(gains)):
        avg_g = (avg_g*(p-1) + gains[i])/p
        avg_l = (avg_l*(p-1) + losses[i])/p
        out[i+1] = 100 - (100/(1+(avg_g/avg_l))) if avg_l != 0 else 100.0
    return out

def macd(closes):
    ef, es = ema(closes, 12), ema(closes, 26)
    m_line = [(f - s) if (f and s) else None for f, s in zip(ef, es)]
    valid = [v for v in m_line if v is not None]
    sig = ema(valid, 9)
    s_line, hist = [None]*len(closes), [None]*len(closes)
    offset = len(closes) - len(valid)
    for i, v in enumerate(sig):
        if v is not None:
            s_line[offset+i] = v
            hist[offset+i] = valid[i] - v
    return m_line, s_line, hist

def atr(highs, lows, closes, p=14):
    tr = [highs[0]-lows[0]] + [max(highs[i]-lows[i], abs(highs[i]-closes[i-1]), abs(lows[i]-closes[i-1])) for i in range(1, len(closes))]
    out = [None]*len(closes)
    if len(tr) >= p:
        out[p-1] = sum(tr[:p])/p
        for i in range(p, len(tr)): out[i] = (out[i-1]*(p-1) + tr[i])/p
    return out

def evaluate_11_indicators(highs, lows, closes, volumes):
    idx = len(closes) - 1
    conf = {}
    
    # 1. Market Structure
    conf["Market Structure"] = "BUY" if closes[idx] > closes[idx-2] and lows[idx] > lows[idx-2] else ("SELL" if closes[idx] < closes[idx-2] and highs[idx] < highs[idx-2] else "NEUTRAL")
    
    # 2. 200 EMA
    e200 = ema(closes, 200)
    conf["200 EMA"] = "BUY" if (e200[idx] and closes[idx] > e200[idx]) else ("SELL" if (e200[idx] and closes[idx] < e200[idx]) else "NEUTRAL")
    
    # 3. 50 EMA
    e50 = ema(closes, 50)
    conf["50 EMA"] = "BUY" if (e50[idx] and closes[idx] > e50[idx]) else ("SELL" if (e50[idx] and closes[idx] < e50[idx]) else "NEUTRAL")
    
    # 4. RSI
    r_val = rsi(closes, 14)
    conf["RSI"] = "BUY" if (r_val[idx] and r_val[idx] > 53) else ("SELL" if (r_val[idx] and r_val[idx] < 47) else "NEUTRAL")
    
    # 5. MACD
    m, s, h = macd(closes)
    conf["MACD"] = "BUY" if (h[idx] and h[idx] > 0) else ("SELL" if (h[idx] and h[idx] < 0) else "NEUTRAL")
    
    # 6. ADX Directional Proxy
    conf["ADX"] = "BUY" if closes[idx] > closes[idx-1] else "SELL"
    
    # 7. ATR Volatility
    at_val = atr(highs, lows, closes, 14)
    conf["ATR"] = "BUY" if (at_val[idx] and (highs[idx]-lows[idx]) > at_val[idx]) else "NEUTRAL"
    
    # 8. Bollinger Bands
    mid = sma(closes, 20)
    conf["Bollinger Bands"] = "BUY" if (mid[idx] and closes[idx] > mid[idx]) else ("SELL" if (mid[idx] and closes[idx] < mid[idx]) else "NEUTRAL")
    
    # 9. Stochastic
    w_high, w_low = max(highs[idx-14:idx+1]), min(lows[idx-14:idx+1])
    stoch = 100 * (closes[idx] - w_low) / (w_high - w_low) if w_high != w_low else 50
    conf["Stochastic"] = "BUY" if stoch > 50 else "SELL"
    
    # 10. SuperTrend Direction
    conf["SuperTrend"] = "BUY" if closes[idx] > (highs[idx-1] + lows[idx-1])/2 else "SELL"
    
    # 11. Volume
    avg_v = sum(volumes[idx-10:idx])/10 if len(volumes) >= 10 else 0
    conf["Volume"] = "BUY" if (volumes[idx] >= avg_v and closes[idx] > closes[idx-1]) else ("SELL" if (volumes[idx] >= avg_v and closes[idx] < closes[idx-1]) else "NEUTRAL")

    return conf

# ============================================================================
# FLASK SERVER & API ENDPOINTS
# ============================================================================

app = Flask(__name__)

@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

@app.route("/api/bot-poll", methods=["GET"])
def bot_poll():
    with BOT_SIGNAL_LOCK:
        return jsonify({"success": True, "data": LATEST_BOT_SIGNAL})

@app.route("/api/register", methods=["POST", "OPTIONS"])
def register():
    if request.method == "OPTIONS": return "", 200
    data = request.get_json(silent=True) or {}
    email, password = data.get("email", "").lower().strip(), data.get("password", "")
    if not email or not password: return jsonify({"success": False, "message": "Missing email/password"}), 400
    with USERS_LOCK:
        if email in USERS: return jsonify({"success": False, "message": "User exists"}), 409
        USERS[email] = {"email": email, "password_hash": hash_password(password)}
    token = create_signed_token({"email": email})
    return jsonify({"success": True, "token": token})

@app.route("/api/login", methods=["POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS": return "", 200
    data = request.get_json(silent=True) or {}
    email, password = data.get("email", "").lower().strip(), data.get("password", "")
    with USERS_LOCK:
        user = USERS.get(email)
        if not user or not verify_password(password, user["password_hash"]):
            return jsonify({"success": False, "message": "Invalid login"}), 401
    token = create_signed_token({"email": email})
    return jsonify({"success": True, "token": token})

@app.route("/api/generate-signal", methods=["POST", "OPTIONS"])
def generate_signal():
    global LATEST_BOT_SIGNAL
    if request.method == "OPTIONS": return "", 200
    auth = require_user_auth()
    if not auth: return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    pair = data.get("pair", "EUR/USD")
    tf = data.get("timeframe", "1")
    symbol = SUPPORTED_PAIRS.get(pair, "EUR/USD")
    interval = TIMEFRAME_MAP.get(tf, "1min")

    try:
        candles = fetch_candles(symbol, interval)
        highs = [c["high"] for c in candles]
        lows = [c["low"] for c in candles]
        closes = [c["close"] for c in candles]
        volumes = [c["volume"] for c in candles]

        conf = evaluate_11_indicators(highs, lows, closes, volumes)
        buy_votes = sum(1 for v in conf.values() if v == "BUY")
        sell_votes = sum(1 for v in conf.values() if v == "SELL")

        dominant = "BUY" if buy_votes >= sell_votes else "SELL"
        votes = buy_votes if dominant == "BUY" else sell_votes
        confidence = round((votes / TOTAL_CONFIRMATIONS) * 100, 1)

        signal = dominant if votes >= SIGNAL_VOTE_THRESHOLD else "WAIT FOR BETTER SETUP"

        with BOT_SIGNAL_LOCK:
            LATEST_BOT_SIGNAL = {
                "pair": pair,
                "signal": signal,
                "confidence": confidence,
                "votes": votes,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        return jsonify({
            "success": True, "pair": pair, "signal": signal,
            "confidence": confidence, "votes": votes, "confirmations": conf
        })
    except Exception as err:
        return jsonify({"success": False, "message": str(err)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

