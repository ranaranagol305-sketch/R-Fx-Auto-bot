"""
R Fx Bot - Backend
====================
1) SIGNAL ENGINE
   Real TwelveData-powered NEXT-CANDLE forex signals using 11 real,
   mathematically-calculated confirmations, all equal weight:
   Market Structure, 200 EMA (slope-filtered), 50 EMA (slope-filtered),
   RSI, MACD, ADX, ATR, Bollinger Bands, Stochastic Oscillator,
   SuperTrend, Volume.

   STRICT RULE: a BUY/SELL signal is only produced when at least 9 of the
   11 confirmations agree on the same direction (9, 10, or 11 out of 11).
   8 or fewer agreeing (including ties) is always WAIT FOR BETTER SETUP.
   No random numbers, no fake confidence, no repainting, no future candle
   data ever used.

   PAIR MODE: "Single Pair Mode" analyzes only the selected pair.
   "Auto Scanning Mode" scans all 13 supported pairs and returns a real
   signal only if at least one pair actually reaches the 9/11 threshold;
   if none do, the result is WAIT FOR BETTER SETUP (never a forced guess).

2) ACCOUNT SYSTEM
   Simple email/password accounts. Per explicit requirement, this does NOT
   use any external database - accounts are kept in the backend process's
   memory only. Register once, then log back in with the same email and
   password. Passwords are hashed (never stored in plain text) using
   PBKDF2-HMAC-SHA256, standard library only.

   Note: because there is no database, accounts are lost if the backend
   process restarts/redeploys. This is intentional, per requirement.

Run:
    pip install flask requests
    python backend.py
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
HIGHER_TIMEFRAME_MAP = {"1min": "15min", "5min": "1h", "15min": "4h", "30min": "4h", "1h": "1day"}
TIMEFRAME_MINUTES = {"1min": 1, "5min": 5, "15min": 15, "30min": 30, "1h": 60, "4h": 240, "1day": 1440}

TOTAL_CONFIRMATIONS = 11
SIGNAL_VOTE_THRESHOLD = 9  # out of 11 - 8 or fewer is always WAIT

SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-secret-key-in-railway")
USER_TOKEN_MAX_AGE_SECONDS = 60 * 60 * 24 * 7  # 7 days

# ============================================================================
# LOGGING
# ============================================================================

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend.log")
logger = logging.getLogger("rana_fx_bot")
logger.setLevel(logging.INFO)
_file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
_console_handler = logging.StreamHandler()
_formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
_file_handler.setFormatter(_formatter)
_console_handler.setFormatter(_formatter)
logger.addHandler(_file_handler)
logger.addHandler(_console_handler)


# ============================================================================
# PASSWORD HASHING (standard library only - PBKDF2-HMAC-SHA256)
# ============================================================================

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


# ============================================================================
# SIGNED SESSION TOKENS (standard library only - HMAC signed + timestamped)
# ============================================================================

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
        if not hmac.compare_digest(expected_sig, sig):
            return None
        padded = body + "=" * (-len(body) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("utf-8"))
        payload = json.loads(raw)
        if int(time.time()) - payload.get("_ts", 0) > max_age_seconds:
            return None
        return payload
    except Exception:
        return None


def get_bearer_token():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    return None


def require_user_auth():
    token = get_bearer_token()
    if not token:
        return None
    return verify_signed_token(token, USER_TOKEN_MAX_AGE_SECONDS)


# ============================================================================
# ACCOUNTS - in-memory only, per explicit requirement (no external database)
# ============================================================================

USERS = {}  # email (lowercase) -> {first_name, last_name, email, mobile, password_hash}
USERS_LOCK = threading.Lock()

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MOBILE_REGEX = re.compile(r"^\+?[0-9\s-]{7,20}$")


def is_valid_email(value):
    return bool(EMAIL_REGEX.match(value or ""))


def is_valid_mobile(value):
    return bool(MOBILE_REGEX.match(value or ""))


def is_valid_password(value):
    if not value or len(value) < 8:
        return False
    if not re.search(r"[A-Za-z]", value):
        return False
    if not re.search(r"[0-9]", value):
        return False
    return True


# ============================================================================
# SIGNAL ENGINE - shared math primitives
# ============================================================================

class AllApiKeysExhaustedError(Exception):
    pass


class MarketDataError(Exception):
    pass


class ApiKeyManager:
    def __init__(self, keys):
        self._keys = list(keys)
        self._active_index = 0
        self._exhausted_until = {}
        self._lock = threading.Lock()

    def _is_exhausted(self, key):
        until = self._exhausted_until.get(key)
        if until is None:
            return False
        if datetime.now(timezone.utc) >= until:
            del self._exhausted_until[key]
            return False
        return True

    def get_active_key(self):
        with self._lock:
            n = len(self._keys)
            for offset in range(n):
                idx = (self._active_index + offset) % n
                key = self._keys[idx]
                if not self._is_exhausted(key):
                    self._active_index = idx
                    return key
            return None

    def mark_current_exhausted(self, key):
        with self._lock:
            self._exhausted_until[key] = datetime.now(timezone.utc) + timedelta(minutes=2)
            self._active_index = (self._keys.index(key) + 1) % len(self._keys)
            logger.warning("API key ending in %s marked exhausted, rotating.", key[-4:])

    def status(self):
        with self._lock:
            return [{"key_suffix": k[-4:], "exhausted": self._is_exhausted(k)} for k in self._keys]


api_key_manager = ApiKeyManager(TWELVEDATA_API_KEYS)


def fetch_candles(symbol, interval, output_size=260):
    attempts = len(TWELVEDATA_API_KEYS)
    last_error = None
    for _ in range(attempts):
        key = api_key_manager.get_active_key()
        if key is None:
            raise AllApiKeysExhaustedError("All TwelveData API keys have reached their request limit.")
        params = {"symbol": symbol, "interval": interval, "outputsize": output_size, "apikey": key, "order": "ASC"}
        try:
            resp = requests.get(TWELVEDATA_BASE_URL, params=params, timeout=15)
        except requests.RequestException as exc:
            raise MarketDataError(f"Network error contacting market data provider: {exc}")
        try:
            payload = resp.json()
        except ValueError:
            raise MarketDataError("Invalid JSON response from TwelveData")
        if payload.get("status") == "error":
            message = str(payload.get("message", "")).lower()
            code = payload.get("code")
            if code == 429 or "credit" in message or "limit" in message:
                api_key_manager.mark_current_exhausted(key)
                last_error = payload.get("message")
                continue
            raise MarketDataError(payload.get("message", "Unknown TwelveData error"))
        values = payload.get("values")
        if not values:
            raise MarketDataError("TwelveData returned no candle data for this symbol/interval.")
        candles = []
        for row in values:
            try:
                dt_str = row["datetime"]
                candle_dt = (
                    datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                    if len(dt_str) > 10 else
                    datetime.strptime(dt_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                )
                candles.append({
                    "datetime": candle_dt, "open": float(row["open"]), "high": float(row["high"]),
                    "low": float(row["low"]), "close": float(row["close"]),
                    "volume": float(row["volume"]) if row.get("volume") not in (None, "") else 0.0,
                })
            except (KeyError, ValueError):
                pass
        candles.sort(key=lambda c: c["datetime"])
        return candles
    raise AllApiKeysExhaustedError(last_error or "All TwelveData API keys are exhausted.")


def get_market_status():
    now = datetime.now(timezone.utc)
    weekday = now.weekday()
    hour = now.hour
    if weekday == 5:
        return "closed"
    if weekday == 4 and hour >= 22:
        return "closed"
    if weekday == 6 and hour < 22:
        return "closed"
    return "open"


def sma(values, period):
    out = [None] * len(values)
    for i in range(period - 1, len(values)):
        out[i] = sum(values[i - period + 1:i + 1]) / period
    return out


def ema(values, period):
    out = [None] * len(values)
    if len(values) < period:
        return out
    seed = sum(values[:period]) / period
    out[period - 1] = seed
    multiplier = 2 / (period + 1)
    for i in range(period, len(values)):
        out[i] = (values[i] - out[i - 1]) * multiplier + out[i - 1]
    return out


def rsi(closes, period=14):
    out = [None] * len(closes)
    if len(closes) <= period:
        return out
    gains, losses = [], []
    for i in range(1, len(closes)):
        change = closes[i] - closes[i - 1]
        gains.append(max(change, 0.0))
        losses.append(max(-change, 0.0))
    avg_gain = sum(gains[:period]) / period
    avg_loss = sum(losses[:period]) / period
    out[period] = _rsi_from_avgs(avg_gain, avg_loss)
    for i in range(period, len(gains)):
        avg_gain = (avg_gain * (period - 1) + gains[i]) / period
        avg_loss = (avg_loss * (period - 1) + losses[i]) / period
        out[i + 1] = _rsi_from_avgs(avg_gain, avg_loss)
    return out


def _rsi_from_avgs(avg_gain, avg_loss):
    if avg_loss == 0:
        return 100.0
    rs = avg_gain / avg_loss
    return 100 - (100 / (1 + rs))


def macd(closes, fast=12, slow=26, signal=9):
    ema_fast = ema(closes, fast)
    ema_slow = ema(closes, slow)
    macd_line = [(f - s) if (f is not None and s is not None) else None for f, s in zip(ema_fast, ema_slow)]
    first_valid = next((i for i, v in enumerate(macd_line) if v is not None), None)
    signal_line = [None] * len(closes)
    histogram = [None] * len(closes)
    if first_valid is not None:
        valid_macd = macd_line[first_valid:]
        sig = ema(valid_macd, signal)
        for i, v in enumerate(sig):
            if v is not None:
                signal_line[first_valid + i] = v
                histogram[first_valid + i] = valid_macd[i] - v
    return macd_line, signal_line, histogram


def true_range(highs, lows, closes):
    tr = [None] * len(closes)
    tr[0] = highs[0] - lows[0]
    for i in range(1, len(closes)):
        tr[i] = max(highs[i] - lows[i], abs(highs[i] - closes[i - 1]), abs(lows[i] - closes[i - 1]))
    return tr


def wilder_smooth(values, period):
    out = [None] * len(values)
    if len(values) < period:
        return out
    seed = sum(values[:period]) / period
    out[period - 1] = seed
    for i in range(period, len(values)):
        out[i] = (out[i - 1] * (period - 1) + values[i]) / period
    return out


def atr(highs, lows, closes, period=14):
    tr = true_range(highs, lows, closes)
    return wilder_smooth(tr, period)


def adx(highs, lows, closes, period=14):
    n = len(closes)
    plus_dm = [0.0] * n
    minus_dm = [0.0] * n
    for i in range(1, n):
        up_move = highs[i] - highs[i - 1]
        down_move = lows[i - 1] - lows[i]
        plus_dm[i] = up_move if (up_move > down_move and up_move > 0) else 0.0
        minus_dm[i] = down_move if (down_move > up_move and down_move > 0) else 0.0
    tr = true_range(highs, lows, closes)
    smoothed_tr = wilder_smooth(tr, period)
    smoothed_plus_dm = wilder_smooth(plus_dm, period)
    smoothed_minus_dm = wilder_smooth(minus_dm, period)
    plus_di = [None] * n
    minus_di = [None] * n
    dx = [None] * n
    for i in range(n):
        if smoothed_tr[i] and smoothed_plus_dm[i] is not None and smoothed_minus_dm[i] is not None and smoothed_tr[i] != 0:
            plus_di[i] = 100 * smoothed_plus_dm[i] / smoothed_tr[i]
            minus_di[i] = 100 * smoothed_minus_dm[i] / smoothed_tr[i]
            denom = plus_di[i] + minus_di[i]
            dx[i] = 100 * abs(plus_di[i] - minus_di[i]) / denom if denom != 0 else 0.0
    first_dx = next((i for i, v in enumerate(dx) if v is not None), None)
    adx_line = [None] * n
    if first_dx is not None:
        valid_dx = [v for v in dx[first_dx:] if v is not None]
        smoothed = wilder_smooth(valid_dx, period)
        for i, v in enumerate(smoothed):
            if v is not None:
                adx_line[first_dx + i] = v
    return adx_line, plus_di, minus_di


def bollinger_bands(closes, period=20, num_std=2):
    middle = sma(closes, period)
    upper = [None] * len(closes)
    lower = [None] * len(closes)
    for i in range(period - 1, len(closes)):
        window = closes[i - period + 1:i + 1]
        mean = middle[i]
        variance = sum((x - mean) ** 2 for x in window) / period
        std = variance ** 0.5
        upper[i] = mean + num_std * std
        lower[i] = mean - num_std * std
    return upper, middle, lower


def stochastic_oscillator(highs, lows, closes, k_period=14, d_period=3):
    n = len(closes)
    k_values = [None] * n
    for i in range(k_period - 1, n):
        window_high = max(highs[i - k_period + 1:i + 1])
        window_low = min(lows[i - k_period + 1:i + 1])
        if window_high - window_low == 0:
            k_values[i] = 50.0
        else:
            k_values[i] = 100 * (closes[i] - window_low) / (window_high - window_low)
    d_values = [None] * n
    for i in range(n):
        window = [k_values[j] for j in range(max(0, i - d_period + 1), i + 1) if k_values[j] is not None]
        if len(window) == d_period:
            d_values[i] = sum(window) / d_period
    return k_values, d_values


def supertrend(highs, lows, closes, period=10, multiplier=3.0):
    n = len(closes)
    atr_values = atr(highs, lows, closes, period)
    hl2 = [(highs[i] + lows[i]) / 2 for i in range(n)]
    final_upper = [None] * n
    final_lower = [None] * n
    trend = [None] * n
    for i in range(n):
        if atr_values[i] is None:
            continue
        basic_upper = hl2[i] + multiplier * atr_values[i]
        basic_lower = hl2[i] - multiplier * atr_values[i]
        prev_final_upper = final_upper[i - 1] if i > 0 else None
        prev_final_lower = final_lower[i - 1] if i > 0 else None
        final_upper[i] = (basic_upper if (prev_final_upper is None or basic_upper < prev_final_upper or closes[i - 1] > prev_final_upper) else prev_final_upper)
        final_lower[i] = (basic_lower if (prev_final_lower is None or basic_lower > prev_final_lower or closes[i - 1] < prev_final_lower) else prev_final_lower)
        if i == 0 or trend[i - 1] is None:
            trend[i] = "up" if closes[i] > final_upper[i] else "down"
        elif trend[i - 1] == "up":
            trend[i] = "down" if closes[i] < final_lower[i] else "up"
        else:
            trend[i] = "up" if closes[i] > final_upper[i] else "down"
    return trend


def find_swing_points(highs, lows, window=3):
    n = len(highs)
    swing_highs, swing_lows = [], []
    for i in range(window, n - window):
        left_h, right_h = highs[i - window:i], highs[i + 1:i + 1 + window]
        if highs[i] >= max(left_h) and highs[i] >= max(right_h):
            swing_highs.append((i, highs[i]))
        left_l, right_l = lows[i - window:i], lows[i + 1:i + 1 + window]
        if lows[i] <= min(left_l) and lows[i] <= min(right_l):
            swing_lows.append((i, lows[i]))
    return swing_highs, swing_lows


# ============================================================================
# CONFIRMATION / SIGNAL ENGINE - 11 equal-weight confirmations
# ============================================================================

def evaluate_confirmations(highs, lows, closes, volumes):
    n = len(closes)
    last = n - 1
    confirmations = {}

    # 1. Market Structure
    swing_highs, swing_lows = find_swing_points(highs, lows, window=3)
    recent_highs = [p for _, p in swing_highs[-3:]]
    recent_lows = [p for _, p in swing_lows[-3:]]
    if len(recent_highs) >= 2 and len(recent_lows) >= 2:
        hh = recent_highs[-1] > recent_highs[-2]
        hl = recent_lows[-1] > recent_lows[-2]
        lh = recent_highs[-1] < recent_highs[-2]
        ll = recent_lows[-1] < recent_lows[-2]
        confirmations["Market Structure"] = "BUY" if (hh and hl) else ("SELL" if (lh and ll) else "NEUTRAL")
    else:
        confirmations["Market Structure"] = "NEUTRAL"

    # 2. 200 EMA (slope-filtered)
    ema200 = ema(closes, 200)
    if ema200[last] is not None and last >= 5 and ema200[last - 5] is not None:
        price = closes[last]
        if price > ema200[last] and ema200[last] > ema200[last - 5]:
            confirmations["200 EMA"] = "BUY"
        elif price < ema200[last] and ema200[last] < ema200[last - 5]:
            confirmations["200 EMA"] = "SELL"
        else:
            confirmations["200 EMA"] = "NEUTRAL"
    else:
        confirmations["200 EMA"] = "NEUTRAL"

    # 3. 50 EMA (slope-filtered)
    ema50 = ema(closes, 50)
    if ema50[last] is not None and last >= 3 and ema50[last - 3] is not None:
        price = closes[last]
        if price > ema50[last] and ema50[last] > ema50[last - 3]:
            confirmations["50 EMA"] = "BUY"
        elif price < ema50[last] and ema50[last] < ema50[last - 3]:
            confirmations["50 EMA"] = "SELL"
        else:
            confirmations["50 EMA"] = "NEUTRAL"
    else:
        confirmations["50 EMA"] = "NEUTRAL"

    # 4. RSI
    rsi_values = rsi(closes, 14)
    if rsi_values[last] is not None and rsi_values[last - 1] is not None:
        r, r_prev = rsi_values[last], rsi_values[last - 1]
        confirmations["RSI"] = "BUY" if (r > 55 and r >= r_prev) else ("SELL" if (r < 45 and r <= r_prev) else "NEUTRAL")
    else:
        confirmations["RSI"] = "NEUTRAL"

    # 5. MACD
    macd_line, signal_line, hist = macd(closes)
    if macd_line[last] is not None and signal_line[last] is not None:
        if macd_line[last] > signal_line[last] and hist[last] > 0:
            confirmations["MACD"] = "BUY"
        elif macd_line[last] < signal_line[last] and hist[last] < 0:
            confirmations["MACD"] = "SELL"
        else:
            confirmations["MACD"] = "NEUTRAL"
    else:
        confirmations["MACD"] = "NEUTRAL"

    # 6. ADX
    adx_line, plus_di, minus_di = adx(highs, lows, closes, 14)
    if adx_line[last] is not None and plus_di[last] is not None and minus_di[last] is not None:
        if adx_line[last] >= 20 and plus_di[last] > minus_di[last]:
            confirmations["ADX"] = "BUY"
        elif adx_line[last] >= 20 and minus_di[last] > plus_di[last]:
            confirmations["ADX"] = "SELL"
        else:
            confirmations["ADX"] = "NEUTRAL"
    else:
        confirmations["ADX"] = "NEUTRAL"

    # 7. ATR (breakout momentum)
    atr_values = atr(highs, lows, closes, 14)
    if atr_values[last] is not None and atr_values[last] > 0:
        move = closes[last] - closes[last - 1]
        confirmations["ATR"] = "BUY" if move > 0.5 * atr_values[last] else ("SELL" if move < -0.5 * atr_values[last] else "NEUTRAL")
    else:
        confirmations["ATR"] = "NEUTRAL"

    # 8. Bollinger Bands
    upper, middle, lower = bollinger_bands(closes, 20, 2)
    if middle[last] is not None:
        if closes[last] > middle[last] and closes[last] < upper[last]:
            confirmations["Bollinger Bands"] = "BUY"
        elif closes[last] < middle[last] and closes[last] > lower[last]:
            confirmations["Bollinger Bands"] = "SELL"
        else:
            confirmations["Bollinger Bands"] = "NEUTRAL"
    else:
        confirmations["Bollinger Bands"] = "NEUTRAL"

    # 9. Stochastic Oscillator
    k_values, d_values = stochastic_oscillator(highs, lows, closes, 14, 3)
    if k_values[last] is not None and d_values[last] is not None:
        if k_values[last] > d_values[last] and k_values[last] < 80:
            confirmations["Stochastic"] = "BUY"
        elif k_values[last] < d_values[last] and k_values[last] > 20:
            confirmations["Stochastic"] = "SELL"
        else:
            confirmations["Stochastic"] = "NEUTRAL"
    else:
        confirmations["Stochastic"] = "NEUTRAL"

    # 10. SuperTrend
    st_trend = supertrend(highs, lows, closes, 10, 3.0)
    if st_trend[last] == "up":
        confirmations["SuperTrend"] = "BUY"
    elif st_trend[last] == "down":
        confirmations["SuperTrend"] = "SELL"
    else:
        confirmations["SuperTrend"] = "NEUTRAL"

    # 11. Volume
    if volumes and len(volumes) == n and any(v > 0 for v in volumes[-30:]):
        recent_vols = [v for v in volumes[-21:-1] if v is not None]
        avg_vol = sum(recent_vols) / len(recent_vols) if recent_vols else 0
        current_vol = volumes[last]
        price_up = closes[last] > closes[last - 1]
        confirmations["Volume"] = ("BUY" if price_up else "SELL") if (avg_vol > 0 and current_vol > avg_vol) else "NEUTRAL"
    else:
        confirmations["Volume"] = "NEUTRAL"

    return confirmations


def build_signal(confirmations):
    """
    STRICT equal-weight rule: every one of the 11 confirmations counts the
    same, none is mandatory. A BUY or SELL is only produced when at least
    SIGNAL_VOTE_THRESHOLD (9) of the 11 agree on the same direction.
    8 or fewer (including ties) always resolves to WAIT FOR BETTER SETUP.
    """
    buy_votes = sum(1 for v in confirmations.values() if v == "BUY")
    sell_votes = sum(1 for v in confirmations.values() if v == "SELL")

    dominant = "BUY" if buy_votes >= sell_votes else "SELL"
    votes = buy_votes if dominant == "BUY" else sell_votes
    confidence = round((votes / TOTAL_CONFIRMATIONS) * 100, 1)

    if votes >= SIGNAL_VOTE_THRESHOLD:
        return dominant, confidence, votes
    return "WAIT FOR BETTER SETUP", confidence, votes


def next_candle_time(last_candle_time, interval):
    minutes = TIMEFRAME_MINUTES.get(interval, 1)
    return last_candle_time + timedelta(minutes=minutes)


def compute_levels(candles, highs, lows, closes, signal, symbol):
    decimals = 3 if "JPY" in symbol else (2 if "XAU" in symbol else 5)
    entry_price = round(candles[-1]["close"], decimals)
    atr_values = atr(highs, lows, closes, 14)
    current_atr = atr_values[-1]
    if not current_atr or ("BUY" not in signal and "SELL" not in signal):
        return None
    direction = "BUY" if "BUY" in signal else "SELL"
    if direction == "BUY":
        return {"entry": entry_price, "tp1": round(entry_price + current_atr, decimals),
                "tp2": round(entry_price + current_atr * 2, decimals), "sl": round(entry_price - current_atr * 1.5, decimals)}
    return {"entry": entry_price, "tp1": round(entry_price - current_atr, decimals),
            "tp2": round(entry_price - current_atr * 2, decimals), "sl": round(entry_price + current_atr * 1.5, decimals)}


def analyze_pair(symbol, interval):
    candles = fetch_candles(symbol, interval, output_size=260)
    if len(candles) < 210:
        raise MarketDataError("Not enough historical data for this pair.")
    highs = [c["high"] for c in candles]
    lows = [c["low"] for c in candles]
    closes = [c["close"] for c in candles]
    volumes = [c["volume"] for c in candles]
    confirmations = evaluate_confirmations(highs, lows, closes, volumes)
    signal, confidence, votes = build_signal(confirmations)
    return confirmations, signal, confidence, votes, candles, highs, lows, closes


# ============================================================================
# FLASK APP
# ============================================================================

app = Flask(__name__)


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": datetime.now(timezone.utc).isoformat()})


@app.route("/api/pairs", methods=["GET"])
def get_pairs():
    return jsonify({"pairs": list(SUPPORTED_PAIRS.keys())})


@app.route("/api/market-status", methods=["GET"])
def market_status():
    return jsonify({"status": get_market_status(), "server_time_utc": datetime.now(timezone.utc).isoformat()})


# ----------------------------------------------------------------------------
# ACCOUNT SYSTEM ROUTES  (in-memory only, no database, no Google, no email verification)
# ----------------------------------------------------------------------------

@app.route("/api/register", methods=["POST", "OPTIONS"])
def register():
    if request.method == "OPTIONS":
        return "", 200

    data = request.get_json(silent=True) or {}
    first_name = str(data.get("first_name", "")).strip()
    last_name = str(data.get("last_name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    mobile = str(data.get("mobile", "")).strip()
    password = str(data.get("password", ""))
    confirm_password = str(data.get("confirm_password", ""))

    if not first_name or not last_name:
        return jsonify({"success": False, "message": "Please enter your first and last name."}), 400
    if not is_valid_email(email):
        return jsonify({"success": False, "message": "Please enter a valid email address."}), 400
    if not is_valid_mobile(mobile):
        return jsonify({"success": False, "message": "Please enter a valid mobile number."}), 400
    if not is_valid_password(password):
        return jsonify({"success": False, "message": "Password must be at least 8 characters and include a letter and a number."}), 400
    if password != confirm_password:
        return jsonify({"success": False, "message": "Passwords do not match."}), 400

    with USERS_LOCK:
        if email in USERS:
            return jsonify({"success": False, "message": "This email is already registered."}), 409
        USERS[email] = {
            "first_name": first_name, "last_name": last_name, "email": email,
            "mobile": mobile, "password_hash": hash_password(password),
        }

    token = create_signed_token({"email": email})
    logger.info("New registration: %s", email)

    return jsonify({"success": True, "token": token, "first_name": first_name, "last_name": last_name, "email": email})


@app.route("/api/login", methods=["POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS":
        return "", 200

    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not email or not password:
        return jsonify({"success": False, "message": "Please enter your email and password."}), 400

    with USERS_LOCK:
        user = USERS.get(email)

    if not user or not verify_password(password, user["password_hash"]):
        return jsonify({"success": False, "message": "Invalid email or password."}), 401

    token = create_signed_token({"email": email})
    logger.info("Successful login: %s", email)

    return jsonify({
        "success": True, "token": token,
        "first_name": user["first_name"], "last_name": user["last_name"], "email": user["email"],
    })


# ----------------------------------------------------------------------------
# SIGNAL ROUTE  (requires login, Single Pair Mode or Auto Scanning Mode)
# ----------------------------------------------------------------------------

@app.route("/api/generate-signal", methods=["POST", "OPTIONS"])
def generate_signal():
    if request.method == "OPTIONS":
        return "", 200

    auth_payload = require_user_auth()
    if not auth_payload:
        return jsonify({"success": False, "message": "Please log in to generate signals."}), 401

    data = request.get_json(silent=True) or {}
    pair = str(data.get("pair", "")).strip()
    timeframe = str(data.get("timeframe", "")).strip()
    auto_scan = bool(data.get("auto_scan", False))

    if timeframe not in TIMEFRAME_MAP:
        return jsonify({"success": False, "message": "Unsupported timeframe."}), 400
    if not auto_scan and pair not in SUPPORTED_PAIRS:
        return jsonify({"success": False, "message": "Unsupported currency pair."}), 400

    if get_market_status() == "closed":
        return jsonify({"success": False, "market_status": "closed", "message": "Market Closed"}), 200

    interval = TIMEFRAME_MAP[timeframe]
    pairs_to_scan = list(SUPPORTED_PAIRS.items()) if auto_scan else [(pair, SUPPORTED_PAIRS[pair])]

    best = None  # (votes, pair_label, confirmations, signal, confidence, candles, highs, lows, closes, symbol)
    last_error = None

    for pair_label, symbol in pairs_to_scan:
        try:
            confirmations, signal, confidence, votes, candles, highs, lows, closes = analyze_pair(symbol, interval)
        except AllApiKeysExhaustedError as exc:
            last_error = str(exc)
            break
        except MarketDataError as exc:
            last_error = str(exc)
            continue

        if best is None or votes > best[0]:
            best = (votes, pair_label, confirmations, signal, confidence, candles, highs, lows, closes, symbol)

        # In auto-scan mode, stop early only if we already found a pair that
        # actually clears the strict threshold with the maximum possible votes.
        if not auto_scan:
            break
        if votes >= TOTAL_CONFIRMATIONS:
            break

    if best is None:
        if isinstance(last_error, str) and "limit" in last_error.lower():
            return jsonify({"success": False, "message": last_error}), 503
        return jsonify({"success": False, "message": last_error or "Could not fetch market data. Please try again."}), 502

    votes, pair_label, confirmations, signal, confidence, candles, highs, lows, closes, symbol = best
    last_candle = candles[-1]
    nxt_time = next_candle_time(last_candle["datetime"], interval)
    levels = compute_levels(candles, highs, lows, closes, signal, symbol)

    logger.info("Signal generated | user=%s pair=%s tf=%s signal=%s confidence=%s votes=%s/%s auto_scan=%s",
                auth_payload.get("email"), pair_label, timeframe, signal, confidence, votes, TOTAL_CONFIRMATIONS, auto_scan)

    return jsonify({
        "success": True, "market_status": "open", "pair": pair_label, "timeframe": timeframe,
        "auto_scan": auto_scan, "signal": signal, "confidence": confidence,
        "votes": votes, "total_confirmations": TOTAL_CONFIRMATIONS,
        "next_candle_time": nxt_time.isoformat(), "last_closed_candle_time": last_candle["datetime"].isoformat(),
        "confirmations": confirmations, "levels": levels,
    })


@app.errorhandler(404)
def not_found(_e):
    return jsonify({"success": False, "message": "Endpoint not found."}), 404


@app.errorhandler(500)
def server_error(e):
    logger.exception("Unhandled server error: %s", e)
    return jsonify({"success": False, "message": "Internal server error."}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info("Starting R Fx Bot backend on 0.0.0.0:%s", port)
    app.run(host="0.0.0.0", port=port, debug=False)
