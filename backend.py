"""
R Fx Bot - Backend
Flask + Deriv WebSocket real OHLCV data + 11-confirmation strategy engine.

No fake data. No random candles. No forced signals.
"""

import os
import json
import hashlib
import time
import threading
from datetime import datetime, timezone

import requests
import websocket  # pip install websocket-client
from flask import Flask, jsonify, request

# ============================================================
# CONFIG
# ============================================================

# Deriv only needs an app_id to identify the application - not an account
# API token - for public market data like candles. Note: Deriv app_ids are
# normally purely numeric (e.g. 1089, 36300) - if this one doesn't work,
# double check the numeric "App ID" shown on your app's page at
# https://developers.deriv.com/dashboard
DERIV_APP_ID = os.environ.get("DERIV_APP_ID", "347bUdJSAQ1kxgHmRUkGP")
DERIV_WS_URL = f"wss://ws.derivws.com/websockets/v3?app_id={DERIV_APP_ID}"

# TwelveData kept as a fallback/backup source - if Deriv can't return data
# for a pair (connection issue, symbol problem, etc.) the bot retries that
# pair against TwelveData before giving up on it for this scan.
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

env_keys = os.environ.get("TWELVEDATA_API_KEYS")
if env_keys:
    TWELVEDATA_API_KEYS = [k.strip() for k in env_keys.split(",") if k.strip()]

TWELVEDATA_URL = "https://api.twelvedata.com/time_series"

# Display name -> Deriv forex symbol (TwelveData fallback uses the display
# name directly, e.g. "EUR/USD", since that's its own native format)
PAIRS = {
    "EUR/USD": "frxEURUSD",
    "GBP/USD": "frxGBPUSD",
    "USD/JPY": "frxUSDJPY",
    "USD/CHF": "frxUSDCHF",
    "AUD/USD": "frxAUDUSD",
    "USD/CAD": "frxUSDCAD",
    "EUR/JPY": "frxEURJPY",
    "GBP/JPY": "frxGBPJPY",
    "EUR/GBP": "frxEURGBP",
    "EUR/AUD": "frxEURAUD",
    "AUD/JPY": "frxAUDJPY",
}

OUTPUT_SIZE = 260
MIN_VALID_CANDLES = 210
TOTAL_CONFIRMATIONS = 11
MIN_VOTES_TO_TRADE = 10

app = Flask(__name__)


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

# ============================================================
# TWELVEDATA FALLBACK (REST + key rotation)
# ============================================================

class KeyRotator:
    def __init__(self, keys):
        self.keys = keys
        self.index = 0
        self.exhausted = set()
        self.lock = threading.Lock()

    def current(self):
        with self.lock:
            if len(self.exhausted) >= len(self.keys):
                return None
            return self.keys[self.index]

    def rotate(self):
        with self.lock:
            self.exhausted.add(self.keys[self.index])
            if len(self.exhausted) >= len(self.keys):
                return None
            self.index = (self.index + 1) % len(self.keys)
            while self.keys[self.index] in self.exhausted:
                self.index = (self.index + 1) % len(self.keys)
                if len(self.exhausted) >= len(self.keys):
                    return None
            return self.keys[self.index]

    def reset_cycle(self):
        # Does NOT reset index back to 0 - only clears "exhausted this
        # minute" tracking, so consecutive scans keep rotating through
        # different keys instead of hammering key #1 every time.
        with self.lock:
            self.exhausted = set()


rotator = KeyRotator(TWELVEDATA_API_KEYS)


def is_key_error(status_code, payload):
    if status_code == 429:
        return True
    if isinstance(payload, dict):
        code = payload.get("code")
        msg = str(payload.get("message", "")).lower()
        if code in (429, 400, 401, 403):
            if "credit" in msg or "limit" in msg or "quota" in msg or "api key" in msg:
                return True
        if "run out of api credits" in msg or "quota" in msg or "limit" in msg:
            return True
    return False


def fetch_candles_twelvedata(pair):
    """Fallback fetch for a single pair via TwelveData REST, with key
    rotation. Returns (candles_list_or_None, error_string_or_None)."""
    attempts = 0
    max_attempts = len(rotator.keys)

    while attempts < max_attempts:
        key = rotator.current()
        if key is None:
            return None, "ALL TWELVEDATA API KEYS EXHAUSTED"

        params = {
            "symbol": pair,
            "interval": "1min",
            "outputsize": OUTPUT_SIZE,
            "apikey": key,
            "order": "ASC",
        }

        try:
            resp = requests.get(TWELVEDATA_URL, params=params, timeout=15)
        except requests.RequestException as e:
            return None, f"TWELVEDATA API ERROR: {e}"

        try:
            data = resp.json()
        except ValueError:
            return None, "TWELVEDATA API ERROR: invalid response"

        if isinstance(data, dict) and data.get("status") == "error":
            if is_key_error(resp.status_code, data):
                attempts += 1
                nxt = rotator.rotate()
                if nxt is None:
                    return None, "ALL TWELVEDATA API KEYS EXHAUSTED"
                continue
            return None, f"TWELVEDATA API ERROR: {data.get('message', 'unknown error')}"

        values = data.get("values") if isinstance(data, dict) else None
        if not values:
            return None, "TWELVEDATA API ERROR: no data returned"

        candles = []
        for v in values:
            try:
                candles.append({
                    "time": v["datetime"],
                    "open": float(v["open"]),
                    "high": float(v["high"]),
                    "low": float(v["low"]),
                    "close": float(v["close"]),
                    "volume": float(v["volume"]) if v.get("volume") not in (None, "") else None,
                })
            except (KeyError, ValueError):
                continue

        return candles, None

    return None, "ALL TWELVEDATA API KEYS EXHAUSTED"


# ============================================================
# DERIV MARKET DATA (public - no account token required) - PRIMARY
# ============================================================

# Track last executed signal_key to enforce one-trade-per-candle (server side too)
_last_signal_keys = {}


def fetch_all_candles(pairs_map):
    """Fetch 1-minute candles for every pair over a single Deriv WebSocket
    connection (one request per pair, correlated by req_id). Returns a dict
    of display_name -> (candles_list_or_None, error_string_or_None).
    Never fabricates data - any pair that errors or times out is skipped.
    """
    results = {}

    try:
        ws = websocket.create_connection(DERIV_WS_URL, timeout=15)
    except Exception as e:
        return {name: (None, f"DERIV CONNECTION FAILED: {e}") for name in pairs_map}

    req_id_map = {}
    try:
        for i, (name, symbol) in enumerate(pairs_map.items()):
            req_id = i + 1
            req_id_map[req_id] = name
            req = {
                "ticks_history": symbol,
                "adjust_start_time": 1,
                "count": OUTPUT_SIZE,
                "end": "latest",
                "start": 1,
                "style": "candles",
                "granularity": 60,  # 1 minute
                "req_id": req_id,
            }
            ws.send(json.dumps(req))

        pending = set(req_id_map.keys())
        deadline = time.time() + 30

        while pending and time.time() < deadline:
            try:
                raw = ws.recv()
            except Exception as e:
                break

            try:
                data = json.loads(raw)
            except ValueError:
                continue

            rid = data.get("req_id")
            if rid not in pending:
                continue

            name = req_id_map[rid]
            pending.discard(rid)

            if data.get("error"):
                results[name] = (None, f"DERIV API ERROR: {data['error'].get('message', 'unknown error')}")
                continue

            candles_raw = data.get("candles")
            if not candles_raw:
                results[name] = (None, "DERIV API ERROR: no candle data returned")
                continue

            candles = []
            for c in candles_raw:
                try:
                    candles.append({
                        "time": datetime.fromtimestamp(int(c["epoch"]), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                        "open": float(c["open"]),
                        "high": float(c["high"]),
                        "low": float(c["low"]),
                        "close": float(c["close"]),
                        # Deriv does not provide real traded volume for forex
                        # (it's an OTC market) - leave unset rather than
                        # inventing a number. The volume confirmation in the
                        # strategy already treats missing volume as NEUTRAL.
                        "volume": None,
                    })
                except (KeyError, ValueError, TypeError):
                    continue
            results[name] = (candles, None)

        for rid in pending:
            results[req_id_map[rid]] = (None, "DERIV API ERROR: timed out waiting for response")

    finally:
        try:
            ws.close()
        except Exception:
            pass

    # Fallback: for any pair Deriv couldn't supply, retry via TwelveData.
    rotator.reset_cycle()
    for name in pairs_map:
        candles, err = results.get(name, (None, "no result"))
        if candles is not None:
            continue  # Deriv already succeeded for this pair
        fallback_candles, fallback_err = fetch_candles_twelvedata(name)
        if fallback_candles is not None:
            results[name] = (fallback_candles, None)
        # else: keep the original Deriv error - both sources failed

    return results


# ============================================================
# INDICATOR MATH (pure python, no numpy/pandas)
# ============================================================

def sma(values, period):
    out = [None] * len(values)
    for i in range(period - 1, len(values)):
        out[i] = sum(values[i - period + 1:i + 1]) / period
    return out


def ema(values, period):
    out = [None] * len(values)
    k = 2 / (period + 1)
    seed_idx = period - 1
    if seed_idx >= len(values):
        return out
    seed = sum(values[0:period]) / period
    out[seed_idx] = seed
    for i in range(seed_idx + 1, len(values)):
        out[i] = values[i] * k + out[i - 1] * (1 - k)
    return out


def rsi(closes, period=14):
    out = [None] * len(closes)
    if len(closes) < period + 1:
        return out
    gains, losses = [], []
    for i in range(1, len(closes)):
        change = closes[i] - closes[i - 1]
        gains.append(max(change, 0))
        losses.append(max(-change, 0))

    avg_gain = sum(gains[0:period]) / period
    avg_loss = sum(losses[0:period]) / period
    idx = period  # index in closes corresponding to first RSI value
    rs = avg_gain / avg_loss if avg_loss != 0 else float("inf")
    out[idx] = 100 - (100 / (1 + rs)) if avg_loss != 0 else 100

    for i in range(period, len(gains)):
        avg_gain = (avg_gain * (period - 1) + gains[i]) / period
        avg_loss = (avg_loss * (period - 1) + losses[i]) / period
        rs = avg_gain / avg_loss if avg_loss != 0 else float("inf")
        out[i + 1] = 100 - (100 / (1 + rs)) if avg_loss != 0 else 100

    return out


def macd(closes, fast=12, slow=26, signal_period=9):
    ema_fast = ema(closes, fast)
    ema_slow = ema(closes, slow)
    macd_line = [None] * len(closes)
    for i in range(len(closes)):
        if ema_fast[i] is not None and ema_slow[i] is not None:
            macd_line[i] = ema_fast[i] - ema_slow[i]

    clean = [v for v in macd_line if v is not None]
    signal_clean = ema(clean, signal_period)
    signal_line = [None] * len(closes)
    offset = len(closes) - len(clean)
    for i, v in enumerate(signal_clean):
        if v is not None:
            signal_line[offset + i] = v

    hist = [None] * len(closes)
    for i in range(len(closes)):
        if macd_line[i] is not None and signal_line[i] is not None:
            hist[i] = macd_line[i] - signal_line[i]

    return macd_line, signal_line, hist


def true_range(highs, lows, closes):
    out = [None] * len(closes)
    out[0] = highs[0] - lows[0]
    for i in range(1, len(closes)):
        tr = max(
            highs[i] - lows[i],
            abs(highs[i] - closes[i - 1]),
            abs(lows[i] - closes[i - 1]),
        )
        out[i] = tr
    return out


def wilder_smooth(values, period):
    out = [None] * len(values)
    valid = [v for v in values if v is not None]
    if len(valid) < period:
        return out
    start = next(i for i, v in enumerate(values) if v is not None)
    first = sum(values[start:start + period]) / period
    out[start + period - 1] = first
    prev = first
    for i in range(start + period, len(values)):
        prev = (prev * (period - 1) + values[i]) / period
        out[i] = prev
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
    atr_smooth = wilder_smooth(tr, period)
    plus_dm_smooth = wilder_smooth(plus_dm, period)
    minus_dm_smooth = wilder_smooth(minus_dm, period)

    plus_di = [None] * n
    minus_di = [None] * n
    for i in range(n):
        if atr_smooth[i] not in (None, 0) and plus_dm_smooth[i] is not None:
            plus_di[i] = 100 * plus_dm_smooth[i] / atr_smooth[i]
        if atr_smooth[i] not in (None, 0) and minus_dm_smooth[i] is not None:
            minus_di[i] = 100 * minus_dm_smooth[i] / atr_smooth[i]

    dx = [None] * n
    for i in range(n):
        if plus_di[i] is not None and minus_di[i] is not None:
            denom = plus_di[i] + minus_di[i]
            if denom != 0:
                dx[i] = 100 * abs(plus_di[i] - minus_di[i]) / denom

    adx_line = wilder_smooth(dx, period)
    return adx_line, plus_di, minus_di


def bollinger(closes, period=20, mult=2):
    mid = sma(closes, period)
    upper = [None] * len(closes)
    lower = [None] * len(closes)
    for i in range(period - 1, len(closes)):
        window = closes[i - period + 1:i + 1]
        mean = mid[i]
        variance = sum((c - mean) ** 2 for c in window) / period
        sd = variance ** 0.5
        upper[i] = mean + mult * sd
        lower[i] = mean - mult * sd
    return upper, mid, lower


def stochastic(highs, lows, closes, k_period=14, d_period=3):
    n = len(closes)
    k = [None] * n
    for i in range(k_period - 1, n):
        window_high = max(highs[i - k_period + 1:i + 1])
        window_low = min(lows[i - k_period + 1:i + 1])
        if window_high == window_low:
            k[i] = 50.0
        else:
            k[i] = 100 * (closes[i] - window_low) / (window_high - window_low)

    clean = [v for v in k if v is not None]
    d_clean = sma(clean, d_period)
    d = [None] * n
    offset = n - len(clean)
    for i, v in enumerate(d_clean):
        if v is not None:
            d[offset + i] = v

    return k, d


def supertrend(highs, lows, closes, period=10, mult=3):
    n = len(closes)
    atr_vals = atr(highs, lows, closes, period)
    hl2 = [(highs[i] + lows[i]) / 2 for i in range(n)]

    upperband = [None] * n
    lowerband = [None] * n
    trend = [None] * n  # 1 = up, -1 = down

    for i in range(n):
        if atr_vals[i] is None:
            continue
        basic_upper = hl2[i] + mult * atr_vals[i]
        basic_lower = hl2[i] - mult * atr_vals[i]

        prev_upper = upperband[i - 1] if i > 0 else None
        prev_lower = lowerband[i - 1] if i > 0 else None
        prev_close = closes[i - 1] if i > 0 else None

        if prev_upper is not None:
            final_upper = basic_upper if (basic_upper < prev_upper or prev_close > prev_upper) else prev_upper
        else:
            final_upper = basic_upper

        if prev_lower is not None:
            final_lower = basic_lower if (basic_lower > prev_lower or prev_close < prev_lower) else prev_lower
        else:
            final_lower = basic_lower

        upperband[i] = final_upper
        lowerband[i] = final_lower

        prev_trend = trend[i - 1] if i > 0 else None
        if prev_trend is None:
            trend[i] = 1 if closes[i] > final_upper else -1
        elif prev_trend == 1:
            trend[i] = -1 if closes[i] < final_lower else 1
        else:
            trend[i] = 1 if closes[i] > final_upper else -1

    return trend


def swing_points(highs, lows, left=2, right=2):
    """Return list of (index, 'high'/'low', price) for confirmed swing points."""
    n = len(highs)
    points = []
    for i in range(left, n - right):
        window_high = highs[i - left:i + right + 1]
        window_low = lows[i - left:i + right + 1]
        if highs[i] == max(window_high) and window_high.count(highs[i]) == 1:
            points.append((i, "high", highs[i]))
        if lows[i] == min(window_low) and window_low.count(lows[i]) == 1:
            points.append((i, "low", lows[i]))
    return points


def market_structure(highs, lows):
    points = swing_points(highs, lows)
    swing_highs = [p for p in points if p[1] == "high"]
    swing_lows = [p for p in points if p[1] == "low"]
    if len(swing_highs) < 2 or len(swing_lows) < 2:
        return "NEUTRAL"

    last_high, prev_high = swing_highs[-1][2], swing_highs[-2][2]
    last_low, prev_low = swing_lows[-1][2], swing_lows[-2][2]

    if last_high > prev_high and last_low > prev_low:
        return "BUY"
    if last_high < prev_high and last_low < prev_low:
        return "SELL"
    return "NEUTRAL"


# ============================================================
# STRATEGY: 11 confirmations, equal weight, >=9/11 to trade
# ============================================================

def evaluate_pair(pair, candles):
    closes = [c["close"] for c in candles]
    highs = [c["high"] for c in candles]
    lows = [c["low"] for c in candles]
    volumes = [c["volume"] for c in candles]

    n = len(closes)
    votes = {}

    # 1. Market Structure
    votes["market_structure"] = market_structure(highs, lows)

    # 2. 200 EMA slope filtered
    ema200 = ema(closes, 200)
    if ema200[-1] is not None and ema200[-2] is not None:
        price = closes[-1]
        rising = ema200[-1] > ema200[-2]
        falling = ema200[-1] < ema200[-2]
        if price > ema200[-1] and rising:
            votes["ema200"] = "BUY"
        elif price < ema200[-1] and falling:
            votes["ema200"] = "SELL"
        else:
            votes["ema200"] = "NEUTRAL"
    else:
        votes["ema200"] = "NEUTRAL"

    # 3. 50 EMA slope filtered
    ema50 = ema(closes, 50)
    if ema50[-1] is not None and ema50[-2] is not None:
        price = closes[-1]
        rising = ema50[-1] > ema50[-2]
        falling = ema50[-1] < ema50[-2]
        if price > ema50[-1] and rising:
            votes["ema50"] = "BUY"
        elif price < ema50[-1] and falling:
            votes["ema50"] = "SELL"
        else:
            votes["ema50"] = "NEUTRAL"
    else:
        votes["ema50"] = "NEUTRAL"

    # 4. RSI
    rsi_vals = rsi(closes, 14)
    if rsi_vals[-1] is not None and rsi_vals[-2] is not None:
        r, prev_r = rsi_vals[-1], rsi_vals[-2]
        if r > 55 and r >= prev_r:
            votes["rsi"] = "BUY"
        elif r < 45 and r <= prev_r:
            votes["rsi"] = "SELL"
        else:
            votes["rsi"] = "NEUTRAL"
    else:
        votes["rsi"] = "NEUTRAL"

    # 5. MACD
    macd_line, signal_line, hist = macd(closes)
    if macd_line[-1] is not None and signal_line[-1] is not None and hist[-1] is not None:
        if macd_line[-1] > signal_line[-1] and hist[-1] > 0:
            votes["macd"] = "BUY"
        elif macd_line[-1] < signal_line[-1] and hist[-1] < 0:
            votes["macd"] = "SELL"
        else:
            votes["macd"] = "NEUTRAL"
    else:
        votes["macd"] = "NEUTRAL"

    # 6. ADX
    adx_line, plus_di, minus_di = adx(highs, lows, closes, 14)
    if adx_line[-1] is not None and plus_di[-1] is not None and minus_di[-1] is not None:
        if adx_line[-1] >= 20 and plus_di[-1] > minus_di[-1]:
            votes["adx"] = "BUY"
        elif adx_line[-1] >= 20 and minus_di[-1] > plus_di[-1]:
            votes["adx"] = "SELL"
        else:
            votes["adx"] = "NEUTRAL"
    else:
        votes["adx"] = "NEUTRAL"

    # 7. ATR (movement filter)
    atr_vals = atr(highs, lows, closes, 14)
    if atr_vals[-1] is not None and n >= 2:
        move = closes[-1] - closes[-2]
        if move > 0.5 * atr_vals[-1]:
            votes["atr"] = "BUY"
        elif move < -0.5 * atr_vals[-1]:
            votes["atr"] = "SELL"
        else:
            votes["atr"] = "NEUTRAL"
    else:
        votes["atr"] = "NEUTRAL"

    # 8. Bollinger Bands
    bb_upper, bb_mid, bb_lower = bollinger(closes, 20, 2)
    if bb_upper[-1] is not None and bb_mid[-1] is not None and bb_lower[-1] is not None:
        c = closes[-1]
        if c > bb_mid[-1] and c < bb_upper[-1]:
            votes["bollinger"] = "BUY"
        elif c < bb_mid[-1] and c > bb_lower[-1]:
            votes["bollinger"] = "SELL"
        else:
            votes["bollinger"] = "NEUTRAL"
    else:
        votes["bollinger"] = "NEUTRAL"

    # 9. Stochastic
    stoch_k, stoch_d = stochastic(highs, lows, closes, 14, 3)
    if stoch_k[-1] is not None and stoch_d[-1] is not None:
        k, d = stoch_k[-1], stoch_d[-1]
        if k > d and k < 80:
            votes["stochastic"] = "BUY"
        elif k < d and k > 20:
            votes["stochastic"] = "SELL"
        else:
            votes["stochastic"] = "NEUTRAL"
    else:
        votes["stochastic"] = "NEUTRAL"

    # 10. SuperTrend
    st = supertrend(highs, lows, closes, 10, 3)
    if st[-1] == 1:
        votes["supertrend"] = "BUY"
    elif st[-1] == -1:
        votes["supertrend"] = "SELL"
    else:
        votes["supertrend"] = "NEUTRAL"

    # 11. Volume
    usable_volume = all(v is not None and v > 0 for v in volumes[-21:]) if n >= 21 else False
    if usable_volume:
        avg_vol = sum(volumes[-21:-1]) / 20
        cur_vol = volumes[-1]
        price_up = closes[-1] > closes[-2]
        price_down = closes[-1] < closes[-2]
        if cur_vol > avg_vol and price_up:
            votes["volume"] = "BUY"
        elif cur_vol > avg_vol and price_down:
            votes["volume"] = "SELL"
        else:
            votes["volume"] = "NEUTRAL"
    else:
        votes["volume"] = "NEUTRAL"

    buy_votes = sum(1 for v in votes.values() if v == "BUY")
    sell_votes = sum(1 for v in votes.values() if v == "SELL")

    if buy_votes >= MIN_VOTES_TO_TRADE and buy_votes > sell_votes:
        direction = "BUY"
        vote_count = buy_votes
    elif sell_votes >= MIN_VOTES_TO_TRADE and sell_votes > buy_votes:
        direction = "SELL"
        vote_count = sell_votes
    else:
        direction = "WAIT"
        vote_count = max(buy_votes, sell_votes)

    confidence = round((vote_count / TOTAL_CONFIRMATIONS) * 100, 1)

    return {
        "pair": pair,
        "direction": direction,
        "votes": vote_count,
        "buy_votes": buy_votes,
        "sell_votes": sell_votes,
        "confidence": confidence,
        "confirmations": votes,
        "last_closed_candle_time": candles[-1]["time"],
    }


def make_signal_key(pair, candle_time, direction, votes):
    raw = f"{pair}|{candle_time}|{direction}|{votes}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def next_candle_time_str(last_closed_time):
    try:
        dt = datetime.strptime(last_closed_time, "%Y-%m-%d %H:%M:%S")
        nxt = dt.replace(second=0) 
        nxt = nxt.timestamp() + 60
        return datetime.fromtimestamp(nxt, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


# ============================================================
# MARKET STATUS
# ============================================================

def get_market_status():
    """Forex-style market: closed roughly Fri 22:00 UTC -> Sun 22:00 UTC."""
    now = datetime.now(timezone.utc)
    weekday = now.weekday()  # Mon=0 ... Sun=6
    hour = now.hour

    if weekday == 5:  # Saturday
        return "closed"
    if weekday == 6 and hour < 22:  # Sunday before 22:00 UTC
        return "closed"
    if weekday == 4 and hour >= 22:  # Friday after 22:00 UTC
        return "closed"
    return "open"


# ============================================================
# ROUTES
# ============================================================

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "R Fx Bot"})


@app.route("/api/market-status", methods=["GET"])
def market_status():
    status = get_market_status()
    if status == "closed":
        return jsonify({
            "success": True,
            "market_status": "closed",
            "message": "MARKET CLOSED",
        })
    return jsonify({
        "success": True,
        "market_status": "open",
        "message": "MARKET OPEN",
    })


@app.route("/api/extension/scan", methods=["POST", "OPTIONS"])
def extension_scan():
    if request.method == "OPTIONS":
        return "", 204

    status = get_market_status()
    if status == "closed":
        return jsonify({
            "success": True,
            "market_status": "closed",
            "selected": False,
            "signal": "WAIT FOR BETTER SETUP",
            "display_signal": "WAIT",
            "message": "MARKET CLOSED",
        })

    fetch_results = fetch_all_candles(PAIRS)

    # If every single pair failed (e.g. Deriv connection down entirely),
    # surface that clearly instead of silently returning WAIT.
    if all(err is not None for _, err in fetch_results.values()):
        first_error = next(iter(fetch_results.values()))[1]
        return jsonify({
            "success": False,
            "error": first_error or "DERIV CONNECTION FAILED",
        }), 200

    results = []
    for pair in PAIRS:
        candles, err = fetch_results.get(pair, (None, "DERIV API ERROR: no response"))

        if err is not None or candles is None:
            continue

        if len(candles) < MIN_VALID_CANDLES:
            continue

        result = evaluate_pair(pair, candles)
        results.append(result)

    tradable = [r for r in results if r["direction"] in ("BUY", "SELL")]

    if not tradable:
        return jsonify({
            "success": True,
            "market_status": "open",
            "selected": False,
            "signal": "WAIT FOR BETTER SETUP",
            "display_signal": "WAIT",
            "timeframe": "1",
            "timeframe_label": "1 min",
            "scanned_pairs": len(results),
        })

    # Priority: highest votes first, confidence as tie-breaker
    tradable.sort(key=lambda r: (r["votes"], r["confidence"]), reverse=True)
    best = tradable[0]

    signal_key = make_signal_key(
        best["pair"], best["last_closed_candle_time"], best["direction"], best["votes"]
    )
    next_candle = next_candle_time_str(best["last_closed_candle_time"])

    display_signal = "UP" if best["direction"] == "BUY" else "DOWN"

    return jsonify({
        "success": True,
        "market_status": "open",
        "selected": True,
        "pair": best["pair"],
        "signal": best["direction"],
        "display_signal": display_signal,
        "votes": best["votes"],
        "total_confirmations": TOTAL_CONFIRMATIONS,
        "confidence": best["confidence"],
        "timeframe": "1",
        "timeframe_label": "1 min",
        "last_closed_candle_time": best["last_closed_candle_time"],
        "next_candle_time": next_candle,
        "signal_key": signal_key,
        "confirmations": best["confirmations"],
    })


if __name__ == "__main__":
    PORT = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=PORT)
