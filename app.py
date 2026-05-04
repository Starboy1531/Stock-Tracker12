"""Stock Tracker — Flask application entry point."""

import json
import os
import tempfile
import time
from datetime import date, datetime
from typing import Any, Dict, List, Optional

import requests
import yfinance as yf
from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_dance.contrib.google import google, make_google_blueprint
from flask_dance.consumer import oauth_authorized
from flask_session import Session
from werkzeug.utils import secure_filename


load_dotenv(override=True)

_COMMON_US_TICKERS = frozenset(
    {
        "AAPL",
        "MSFT",
        "GOOGL",
        "GOOG",
        "AMZN",
        "META",
        "NVDA",
        "TSLA",
        "AMD",
        "NFLX",
        "DIS",
        "BA",
        "INTC",
        "CSCO",
        "PFE",
        "XOM",
        "WMT",
        "JPM",
        "V",
        "MA",
        "HD",
        "PG",
        "UNH",
        "ABBV",
        "KO",
        "PEP",
        "COST",
        "MRK",
        "T",
        "F",
        "GE",
        "BAC",
        "WFC",
        "C",
        "GS",
        "MS",
        "PYPL",
        "ADBE",
        "CRM",
        "NKE",
        "SBUX",
        "MCD",
        "IBM",
        "ORCL",
        "QCOM",
        "TXN",
        "AVGO",
        "NOW",
        "SHOP",
    }
)


def normalize_stock_symbol(raw: str, market: Optional[str] = None) -> str:
    """Uppercase; append .NS for likely NSE symbols; leave US tickers and crypto as-is."""
    s = (raw or "").strip().upper()
    if not s:
        return s
    if "." in s or "-" in s or "=" in s:
        return s
    m = (market or "").strip()
    if m == "NASDAQ/NYSE":
        return s
    if m == "Crypto":
        if not s.endswith("-USD"):
            return f"{s}-USD"
        return s
    if m in ("Forex", "Commodities", "Derivatives"):
        return s
    if s in _COMMON_US_TICKERS:
        return s
    return f"{s}.NS"


def get_live_price(symbol: str) -> Optional[float]:
    """Latest close or quote price for stocks, crypto (e.g. BTC-USD), and indices."""
    try:
        symbol = symbol.upper().strip()
        ticker = yf.Ticker(symbol)

        # Try fast_info first (fastest)
        try:
            price = ticker.fast_info.last_price
            if price and price > 0:
                return round(float(price), 2)
        except Exception:
            pass

        # Try 1 minute history
        try:
            data = ticker.history(period="1d", interval="1m")
            if not data.empty:
                return round(float(data["Close"].iloc[-1]), 2)
        except Exception:
            pass

        # Try daily history as last resort
        try:
            data = ticker.history(period="2d")
            if not data.empty:
                return round(float(data["Close"].iloc[-1]), 2)
        except Exception:
            pass

        return None
    except Exception as e:
        print(f"Price error for {symbol}: {e}")
        return None


def _quote_price_fast_preferred(symbol: str) -> Optional[float]:
    """Latest quote: fast_info first (fast), optional 1m intraday fallback."""
    sym = (symbol or "").strip().upper()
    if not sym:
        return None
    try:
        ticker = yf.Ticker(sym)
        fast = ticker.fast_info
        price = getattr(fast, "last_price", None)
        if price is None and hasattr(fast, "get"):
            price = fast.get("last_price")  # type: ignore[union-attr]
        if price:
            return round(float(price), 2)
        data = ticker.history(period="1d", interval="1m")
        if data is not None and not data.empty:
            return round(float(data["Close"].iloc[-1]), 2)
    except Exception:
        return None
    return None


app = Flask(__name__)
app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = "stocktracker2026secretkey"
app.config["SESSION_FILE_DIR"] = os.path.join(tempfile.gettempdir(), "stock_tracker_sessions")
os.makedirs(app.config["SESSION_FILE_DIR"], exist_ok=True)
app.config["SESSION_PERMANENT"] = False
app.config["MAIL_SERVER"] = "smtp-mail.outlook.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_USERNAME")
Session(app)

google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID", ""),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET", ""),
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
    ],
)
app.register_blueprint(google_bp, url_prefix="/login")

_AUTH_EXEMPT_ENDPOINTS = frozenset(
    {"login", "signup", "logout", "static", "index", "google.login", "google.authorized", "create_profiles_table"}
)


def _apply_auth_session(
    access_token: str,
    refresh_token: Optional[str],
    user: Dict[str, Any],
) -> None:
    """Store tokens and user identity on the session."""
    session["access_token"] = access_token
    if refresh_token:
        session["refresh_token"] = refresh_token
    uid = user.get("id")
    session["user_id"] = str(uid) if uid is not None else ""
    session["email"] = user.get("email") or ""
    um = user.get("user_metadata") or {}
    name = (um.get("display_name") or um.get("full_name") or "").strip()
    if not name and session["email"]:
        name = session["email"].split("@")[0]
    if not name:
        name = "Investor"
    session["name"] = name


@app.before_request
def _require_user_session():
    if request.endpoint in _AUTH_EXEMPT_ENDPOINTS:
        return None
    if request.endpoint is None:
        return None
    if not session.get("user_id"):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Unauthorized"}), 401
        flash("Please sign in.", "error")
        return redirect(url_for("login"))
    if not session.get("access_token"):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Unauthorized"}), 401
        session.clear()
        flash("Session expired. Please sign in again.", "error")
        return redirect(url_for("login"))
    return None

TIMEZONES = [
    ("Asia/Kolkata", "India — IST (Asia/Kolkata)"),
    ("Asia/Calcutta", "India — IST (Asia/Calcutta, legacy)"),
    ("Asia/Dubai", "UAE — Asia/Dubai"),
    ("Asia/Singapore", "Singapore — Asia/Singapore"),
    ("Asia/Hong_Kong", "Hong Kong — Asia/Hong_Kong"),
    ("Asia/Tokyo", "Japan — Asia/Tokyo"),
    ("Asia/Seoul", "South Korea — Asia/Seoul"),
    ("Asia/Shanghai", "China — Asia/Shanghai"),
    ("Asia/Bangkok", "Thailand — Asia/Bangkok"),
    ("Asia/Jakarta", "Indonesia — Asia/Jakarta"),
    ("Asia/Manila", "Philippines — Asia/Manila"),
    ("Australia/Sydney", "Australia — Sydney"),
    ("Australia/Melbourne", "Australia — Melbourne"),
    ("Pacific/Auckland", "New Zealand — Pacific/Auckland"),
    ("Europe/London", "UK — Europe/London"),
    ("Europe/Paris", "France — Europe/Paris"),
    ("Europe/Berlin", "Germany — Europe/Berlin"),
    ("Europe/Zurich", "Switzerland — Europe/Zurich"),
    ("America/New_York", "US Eastern — America/New_York"),
    ("America/Chicago", "US Central — America/Chicago"),
    ("America/Denver", "US Mountain — America/Denver"),
    ("America/Los_Angeles", "US Pacific — America/Los_Angeles"),
    ("America/Toronto", "Canada — America/Toronto"),
    ("America/Sao_Paulo", "Brazil — America/Sao_Paulo"),
    ("UTC", "UTC"),
]

CURRENCIES = [
    ("INR", "INR — Indian Rupee (₹)"),
    ("USD", "USD — US Dollar ($)"),
    ("EUR", "EUR — Euro (€)"),
    ("GBP", "GBP — British Pound (£)"),
    ("JPY", "JPY — Japanese Yen (¥)"),
    ("AUD", "AUD — Australian Dollar (A$)"),
    ("CAD", "CAD — Canadian Dollar (C$)"),
    ("SGD", "SGD — Singapore Dollar (S$)"),
    ("AED", "AED — UAE Dirham (د.إ)"),
]

MARKETS = [
    ("NSE/BSE", "NSE / BSE (India)"),
    ("NYSE/NASDAQ", "NYSE / NASDAQ (US)"),
    ("LSE", "London Stock Exchange"),
    ("TSE", "Tokyo Stock Exchange"),
    ("HKEX", "Hong Kong Exchange"),
    ("Other", "Other / Global"),
]

def _supabase_base_url() -> str:
    return os.getenv("SUPABASE_URL", "").rstrip("/")


def _supabase_anon_key() -> str:
    return os.getenv("SUPABASE_KEY", "")


def _auth_headers():
    key = _supabase_anon_key()
    return {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }


def _user_jwt_headers(access_token: str, content_type_json: bool = True):
    key = _supabase_anon_key()
    h = {
        "apikey": key,
        "Authorization": f"Bearer {access_token}",
    }
    if content_type_json:
        h["Content-Type"] = "application/json"
    return h


def _auth_url(path: str) -> str:
    return f"{_supabase_base_url()}{path}"


def _auth_error_message(resp: requests.Response) -> str:
    try:
        data = resp.json()
    except ValueError:
        return (resp.text or resp.reason or "Request failed").strip() or "Request failed"
    return (
        data.get("error_description")
        or data.get("message")
        or data.get("msg")
        or (data.get("error") if isinstance(data.get("error"), str) else None)
        or str(data)
    )


def _initials_from_name(name: str) -> str:
    name = (name or "").strip()
    if not name:
        return "?"
    parts = [p for p in name.replace(".", " ").split() if p]
    if len(parts) >= 2:
        return (parts[0][0] + parts[1][0]).upper()
    return name[:2].upper()


def _fetch_supabase_user(access_token: str) -> Optional[Dict[str, Any]]:
    r = requests.get(
        _auth_url("/auth/v1/user"),
        headers=_user_jwt_headers(access_token),
        timeout=20,
    )
    if not r.ok:
        return None
    return r.json()


def _rest_v1_url() -> str:
    return f"{_supabase_base_url()}/rest/v1"


PORTFOLIOS_DDL_STATEMENTS = [
    """
    create table if not exists public.portfolios (
      id uuid default gen_random_uuid() primary key,
      user_id text not null,
      symbol text not null,
      shares numeric not null,
      avg_price numeric not null,
      buy_date date,
      buy_price numeric,
      created_at timestamp default now()
    )
    """,
    "alter table public.portfolios enable row level security",
    'drop policy if exists "portfolios_select_own" on public.portfolios',
    """
    create policy "portfolios_select_own" on public.portfolios
      for select using (auth.uid()::text = user_id)
    """,
    'drop policy if exists "portfolios_insert_own" on public.portfolios',
    """
    create policy "portfolios_insert_own" on public.portfolios
      for insert with check (auth.uid()::text = user_id)
    """,
    'drop policy if exists "portfolios_update_own" on public.portfolios',
    """
    create policy "portfolios_update_own" on public.portfolios
      for update using (auth.uid()::text = user_id)
    """,
    'drop policy if exists "portfolios_delete_own" on public.portfolios',
    """
    create policy "portfolios_delete_own" on public.portfolios
      for delete using (auth.uid()::text = user_id)
    """,
    "alter table public.portfolios add column if not exists buy_date date",
    "alter table public.portfolios add column if not exists buy_price numeric",
    "alter table public.portfolios add column if not exists status text default 'active'",
    "alter table public.portfolios add column if not exists exit_price numeric",
    "alter table public.portfolios add column if not exists exit_date date",
    "alter table public.portfolios add column if not exists final_pnl numeric",
    "alter table public.portfolios add column if not exists currency text default 'INR'",
    "alter table public.portfolios add column if not exists market text default 'NSE/BSE'",
]


def _fetch_portfolios_for_user(access_token: str, user_id: str) -> List[Dict[str, Any]]:
    base = _supabase_base_url()
    if not base or not user_id:
        return []
    r = requests.get(
        f"{_rest_v1_url()}/portfolios",
        headers=_user_jwt_headers(access_token),
        params={
            "user_id": f"eq.{user_id}",
            "select": "*",
            "order": "created_at.desc",
        },
        timeout=25,
    )
    if not r.ok:
        return []
    data = r.json()
    return data if isinstance(data, list) else []


def _currency_from_ticker(ticker: yf.Ticker, symbol: str) -> str:
    sup = symbol.upper()
    if sup.endswith(".NS") or sup.endswith(".BO"):
        return "INR"
    try:
        fi = ticker.fast_info
        c = fi.get("currency") if hasattr(fi, "get") else None
        if c:
            return str(c).upper()
    except Exception:
        pass
    try:
        info = ticker.info
        if isinstance(info, dict) and info.get("currency"):
            return str(info["currency"]).upper()
    except Exception:
        pass
    return "USD"


def _to_inr(amount: float, currency: str, usd_inr: Optional[float]) -> float:
    cur = (currency or "USD").upper()
    if cur == "INR":
        return amount
    if usd_inr and cur == "USD":
        return amount * usd_inr
    if usd_inr:
        return amount * usd_inr
    return amount


def _format_money_amount(amount: float, currency: str) -> str:
    c = (currency or "USD").upper()
    if c == "INR":
        return "₹" + f"{amount:,.2f}"
    if c == "USD":
        return "$" + f"{amount:,.2f}"
    return f"{amount:,.2f} {c}"


def _shares_detail_label(shares: float, symbol: str) -> str:
    s = float(shares)
    if abs(s - int(s)) < 1e-9 and s >= 1:
        qty = str(int(s))
        return f"{qty} shares"
    return f"{s:g} units"


def _format_buy_date_display(raw: Any) -> str:
    if raw is None or raw == "":
        return "—"
    s = str(raw).strip()
    if not s:
        return "—"
    try:
        d = date.fromisoformat(s[:10])
        return d.strftime("%d %b %Y")
    except ValueError:
        return s[:10]


_MARKET_BADGE_MAP = {
    "NSE/BSE": ("nse", "NSE"),
    "NASDAQ/NYSE": ("nasdaq", "US"),
    "Crypto": ("crypto", "Crypto"),
    "Forex": ("forex", "Forex"),
    "Commodities": ("commodities", "Comm"),
    "Derivatives": ("derivatives", "Deriv"),
}


def _market_badge_info(market: Optional[str]) -> tuple[str, str]:
    m = (market or "NSE/BSE").strip()
    return _MARKET_BADGE_MAP.get(m, ("nse", m))


def _enrich_portfolio_rows(
    rows: List[Dict[str, Any]],
) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    active_rows = [r for r in rows if (r.get("status") or "active") != "closed"]
    if not active_rows:
        z = _format_money_amount(0, "INR")
        return [], {
            "total_invested": 0.0,
            "total_current": 0.0,
            "currencies": {"INR"},
            "today_pnl": 0.0,
            "today_currency": "INR",
            "invested_display": z,
            "current_display": z,
            "current_is_up": True,
            "return_pct": 0.0,
            "today_gain_display": z,
            "summary_gain_line": f"+{z} (+0.00%)",
        }

    usd_inr = get_live_price("USDINR=X")
    enriched: List[Dict[str, Any]] = []
    total_invested_inr = 0.0
    total_current_inr = 0.0
    today_pnl_inr = 0.0

    for r in active_rows:
        sym = (r.get("symbol") or "").strip()
        sym_upper = sym.upper()
        shares = float(r.get("shares") or 0)
        buy_px = r.get("buy_price")
        if buy_px is None:
            buy_px = r.get("avg_price")
        buy = float(buy_px or 0)
        buy_date_raw = r.get("buy_date")
        buy_date_display = _format_buy_date_display(buy_date_raw)
        ticker = yf.Ticker(sym)
        live_price = get_live_price(sym)
        print(f"Symbol: {sym} | Live Price: {live_price} | Shares: {shares} | Current Value: {round(shares * live_price, 2) if live_price else None}")
        stored_cur = (r.get("currency") or "").strip().upper()
        cur = stored_cur if stored_cur else _currency_from_ticker(ticker, sym)
        market = r.get("market") or "NSE/BSE"
        bought_line = f"Bought at {_format_money_amount(buy, cur)} per share"
        cost_basis = shares * buy
        total_invested_inr += _to_inr(cost_basis, cur, usd_inr)

        badge_cls, badge_label = _market_badge_info(market)
        if live_price is None:
            enriched.append(
                {
                    "id": r.get("id"),
                    "symbol": sym,
                    "symbol_display": sym_upper,
                    "buy_date_display": buy_date_display,
                    "bought_at_per_share_display": bought_line,
                    "live_price_display": "Price unavailable",
                    "value_display": "Price unavailable",
                    "pct": None,
                    "pct_class": "na",
                    "gain_loss_amount_display": "—",
                    "gain_class": "",
                    "price_ok": False,
                    "currency": cur,
                    "market": market,
                    "market_badge_class": badge_cls,
                    "market_display": badge_label,
                }
            )
            continue

        current_val_native = shares * live_price
        gain_loss_amount_native = current_val_native - cost_basis
        gain_loss_pct = ((live_price - buy) / buy) * 100 if buy else 0.0
        value_inr = _to_inr(current_val_native, cur, usd_inr)
        gain_amt_inr = _to_inr(gain_loss_amount_native, cur, usd_inr)
        total_current_inr += value_inr

        ga_native_abs = _format_money_amount(abs(gain_loss_amount_native), cur)
        if gain_loss_amount_native >= 0:
            gain_loss_amount_display = "+" + ga_native_abs
        else:
            gain_loss_amount_display = "-" + ga_native_abs

        try:
            h = ticker.history(period="5d", interval="1d", auto_adjust=True)
            c = h["Close"].dropna() if h is not None and not h.empty else None
            if c is not None and len(c) >= 2:
                prev_c = float(c.iloc[-2])
                last_c = float(c.iloc[-1])
                d_pnl_native = shares * (last_c - prev_c)
                today_pnl_inr += _to_inr(d_pnl_native, cur, usd_inr)
        except Exception:
            pass

        enriched.append(
            {
                "id": r.get("id"),
                "symbol": sym,
                "symbol_display": sym_upper,
                "buy_date_display": buy_date_display,
                "bought_at_per_share_display": bought_line,
                "live_price_display": _format_money_amount(live_price, cur) + " / sh.",
                "value_display": _format_money_amount(current_val_native, cur),
                "pct": round(gain_loss_pct, 2),
                "pct_class": "up" if gain_loss_pct >= 0 else "down",
                "gain_loss_amount_display": gain_loss_amount_display,
                "gain_class": "positive" if gain_loss_amount_native >= 0 else "negative",
                "price_ok": True,
                "currency": cur,
                "market": market,
                "market_badge_class": badge_cls,
                "market_display": badge_label,
            }
        )

    metrics: Dict[str, Any] = {
        "total_invested": total_invested_inr,
        "total_current": total_current_inr,
        "currencies": {"INR"},
        "today_pnl": today_pnl_inr,
        "today_currency": "INR",
    }
    metrics["invested_display"] = _format_money_amount(total_invested_inr, "INR")
    metrics["current_display"] = _format_money_amount(total_current_inr, "INR")
    metrics["current_is_up"] = total_current_inr >= total_invested_inr
    if total_invested_inr > 0:
        metrics["return_pct"] = round(
            ((total_current_inr - total_invested_inr) / total_invested_inr) * 100,
            2,
        )
    else:
        metrics["return_pct"] = 0.0
    gain_inr = total_current_inr - total_invested_inr
    rp = float(metrics["return_pct"])
    amt_signed = (
        ("+" if gain_inr >= 0 else "-") + _format_money_amount(abs(gain_inr), "INR")
    )
    metrics["summary_gain_line"] = (
        f"{amt_signed} ({rp:+.2f}%)" if total_invested_inr > 0 else amt_signed
    )
    formatted_day = _format_money_amount(abs(today_pnl_inr), "INR")
    if today_pnl_inr > 0:
        metrics["today_gain_display"] = "+" + formatted_day
    elif today_pnl_inr < 0:
        metrics["today_gain_display"] = "-" + formatted_day
    else:
        metrics["today_gain_display"] = _format_money_amount(0, "INR")
    return enriched, metrics


def _enrich_closed_rows(
    rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    closed_rows = [r for r in rows if (r.get("status") or "active") == "closed"]
    if not closed_rows:
        return []
    usd_inr = get_live_price("USDINR=X")
    enriched: List[Dict[str, Any]] = []
    for r in closed_rows:
        sym = (r.get("symbol") or "").strip()
        sym_upper = sym.upper()
        shares = float(r.get("shares") or 0)
        buy_px = float(r.get("avg_price") or 0)
        exit_px = float(r.get("exit_price") or 0)
        buy_date_raw = r.get("buy_date")
        exit_date_raw = r.get("exit_date")
        buy_date_display = _format_buy_date_display(buy_date_raw)
        exit_date_display = _format_buy_date_display(exit_date_raw)
        ticker = yf.Ticker(sym)
        stored_cur = (r.get("currency") or "").strip().upper()
        cur = stored_cur if stored_cur else _currency_from_ticker(ticker, sym)
        market = r.get("market") or "NSE/BSE"
        badge_cls, badge_label = _market_badge_info(market)
        final_pnl_native = (exit_px - buy_px) * shares
        final_pnl_inr = _to_inr(final_pnl_native, cur, usd_inr)
        final_pnl_pct = 0.0
        if buy_px > 0:
            final_pnl_pct = round(((exit_px - buy_px) / buy_px) * 100, 2)
        days_held = 0
        if buy_date_raw and exit_date_raw:
            try:
                bd = date.fromisoformat(str(buy_date_raw)[:10])
                ed = date.fromisoformat(str(exit_date_raw)[:10])
                days_held = (ed - bd).days
            except ValueError:
                pass
        ga_abs = _format_money_amount(abs(final_pnl_native), cur)
        if final_pnl_native >= 0:
            pnl_display = "+" + ga_abs
        else:
            pnl_display = "-" + ga_abs
        pnl_inr_display = _format_money_amount(final_pnl_inr, "INR")
        enriched.append(
            {
                "id": r.get("id"),
                "symbol": sym,
                "symbol_display": sym_upper,
                "buy_date_display": buy_date_display,
                "exit_date_display": exit_date_display,
                "days_held": days_held,
                "shares": shares,
                "bought_at_per_share_display": _format_money_amount(buy_px, cur),
                "sold_at_per_share_display": _format_money_amount(exit_px, cur),
                "final_pnl": round(final_pnl_native, 2),
                "final_pnl_inr": round(final_pnl_inr, 2),
                "final_pnl_display": pnl_display,
                "final_pnl_inr_display": pnl_inr_display,
                "final_pnl_pct": final_pnl_pct,
                "pnl_class": "positive" if final_pnl_native >= 0 else "negative",
                "currency": cur,
                "market": market,
                "market_badge_class": badge_cls,
                "market_display": badge_label,
            }
        )
    return enriched


def _profit_booked_for_user(access_token: str, user_id: str) -> float:
    rows = _fetch_portfolios_for_user(access_token, user_id)
    closed_rows = [r for r in rows if (r.get("status") or "active") == "closed"]
    if not closed_rows:
        return 0.0
    usd_inr = get_live_price("USDINR=X")
    total = 0.0
    for r in closed_rows:
        stored_cur = (r.get("currency") or "").strip().upper()
        sym = (r.get("symbol") or "").strip()
        if stored_cur:
            cur = stored_cur
        else:
            ticker = yf.Ticker(sym)
            cur = _currency_from_ticker(ticker, sym)
        total += _to_inr(float(r.get("final_pnl") or 0), cur, usd_inr)
    return total


def _portfolio_metrics_for_user(access_token: str, user_id: str) -> Dict[str, Any]:
    rows = _fetch_portfolios_for_user(access_token, user_id)
    _, metrics = _enrich_portfolio_rows(rows)
    active_count = sum(1 for r in rows if (r.get("status") or "active") != "closed")
    metrics["stocks_count"] = active_count
    metrics["profit_booked"] = _profit_booked_for_user(access_token, user_id)
    metrics["profit_booked_display"] = _format_money_amount(metrics["profit_booked"], "INR")
    return metrics


def _avatar_bucket() -> str:
    return os.getenv("SUPABASE_AVATAR_BUCKET", "avatars")


YF_PERIOD_MAP = {
    "1d": ("1d", "15m"),
    "1w": ("5d", "1d"),
    "1m": ("1mo", "1d"),
    "1y": ("1y", "1d"),
}


def _yfinance_stock_payload(symbol: str, period_key: str) -> Dict[str, Any]:
    period_key = period_key if period_key in YF_PERIOD_MAP else "1d"
    yf_period, interval = YF_PERIOD_MAP[period_key]
    ticker = yf.Ticker(symbol)
    hist = ticker.history(period=yf_period, interval=interval, auto_adjust=True)
    if (hist is None or hist.empty) and period_key == "1d":
        hist = ticker.history(period="5d", interval="1d", auto_adjust=True)
        interval = "1d"
    if hist is None or hist.empty:
        hist = ticker.history(period="1mo", interval="1d", auto_adjust=True)
        interval = "1d"
    if hist is None or hist.empty:
        raise ValueError("No price data for this symbol")
    closes = hist["Close"].dropna()
    if closes.empty:
        raise ValueError("No close prices for this symbol")

    labels: list[str] = []
    for ts in closes.index:
        dt = ts.to_pydatetime() if hasattr(ts, "to_pydatetime") else ts
        if interval in ("15m", "5m", "30m", "60m", "1h"):
            labels.append(dt.strftime("%H:%M"))
        else:
            labels.append(dt.strftime("%b %d"))

    prices = [round(float(v), 2) for v in closes.tolist() if v == v]
    if not prices:
        raise ValueError("Invalid price data")
    last_price = prices[-1]

    change_pct = 0.0
    try:
        daily = ticker.history(period="10d", interval="1d", auto_adjust=True)
        daily = daily["Close"].dropna()
        if len(daily) >= 2:
            prev_close = float(daily.iloc[-2])
            if prev_close:
                change_pct = round(((last_price - prev_close) / prev_close) * 100, 2)
        elif len(closes) >= 2:
            first = float(closes.iloc[0])
            if first:
                change_pct = round(((last_price - first) / first) * 100, 2)
    except Exception:
        pass

    currency = "USD"
    try:
        fi = ticker.fast_info
        c = fi.get("currency") if hasattr(fi, "get") else None
        if c is None and isinstance(fi, dict):
            c = fi.get("currency")
        if c:
            currency = str(c)
    except Exception:
        pass
    if currency == "USD":
        try:
            info = ticker.info
            if isinstance(info, dict) and info.get("currency"):
                currency = str(info["currency"])
        except Exception:
            pass

    return {
        "symbol": symbol,
        "period": period_key,
        "labels": labels,
        "prices": prices,
        "last_price": last_price,
        "change_pct": change_pct,
        "currency": currency,
    }


@app.route("/api/stock-price")
def api_stock_price():
    if not session.get("access_token"):
        return jsonify({"error": "Unauthorized"}), 401
    symbol = (request.args.get("symbol") or "").strip()
    period = (request.args.get("period") or "1d").strip().lower()
    if not symbol:
        return jsonify({"error": "symbol is required"}), 400
    if period not in YF_PERIOD_MAP:
        period = "1d"
    try:
        payload = _yfinance_stock_payload(symbol, period)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": str(e) or "Failed to fetch data"}), 500
    return jsonify(payload)


def _rest_error_message(resp: requests.Response) -> str:
    try:
        data = resp.json()
    except ValueError:
        return (resp.text or resp.reason or "Request failed").strip()
    if isinstance(data, dict):
        return (
            data.get("message")
            or data.get("hint")
            or data.get("details")
            or str(data.get("error", data))
        )
    return str(data)


@app.route("/api/create-table", methods=["POST"])
def api_create_table():
    """Create portfolios table. PostgREST cannot run DDL; uses DATABASE_URL if set."""
    if not session.get("access_token"):
        return jsonify({"error": "Unauthorized"}), 401
    db_url = (os.getenv("DATABASE_URL") or "").strip()
    if not db_url:
        return jsonify(
            {
                "ok": False,
                "message": (
                    "Supabase /rest/v1 only exposes tables, not raw DDL. "
                    "Set DATABASE_URL to your Supabase Postgres connection string "
                    "(Dashboard → Project Settings → Database) and POST again, "
                    "or run sql/portfolios.sql in the SQL Editor."
                ),
                "sql": ";\n".join(s.strip() for s in PORTFOLIOS_DDL_STATEMENTS if s.strip()),
            }
        ), 200
    try:
        import psycopg2
    except ImportError:
        return jsonify({"error": "Install psycopg2-binary (pip install psycopg2-binary)"}), 500
    try:
        conn = psycopg2.connect(db_url)
        conn.autocommit = True
        with conn.cursor() as cur:
            for stmt in PORTFOLIOS_DDL_STATEMENTS:
                s = stmt.strip()
                if s:
                    cur.execute(s)
        conn.close()
        return jsonify(
            {"ok": True, "message": "portfolios table and RLS policies created or updated"}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/create-profiles-table")
def create_profiles_table():
    """Create profiles table. Uses DATABASE_URL if set."""
    db_url = (os.getenv("DATABASE_URL") or "").strip()
    if not db_url:
        return jsonify(
            {
                "ok": False,
                "message": (
                    "Set DATABASE_URL to your Supabase Postgres connection string "
                    "(Dashboard → Project Settings → Database) and visit again, "
                    "or run this SQL in the SQL Editor."
                ),
                "sql": ";\n".join(s.strip() for s in PROFILES_DDL_STATEMENTS if s.strip()),
            }
        ), 200
    try:
        import psycopg2
    except ImportError:
        return jsonify({"error": "Install psycopg2-binary (pip install psycopg2-binary)"}), 500
    try:
        conn = psycopg2.connect(db_url)
        conn.autocommit = True
        with conn.cursor() as cur:
            for stmt in PROFILES_DDL_STATEMENTS:
                s = stmt.strip()
                if s:
                    cur.execute(s)
        conn.close()
        return jsonify({"ok": True, "message": "profiles table and RLS policies created or updated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/prices")
def api_prices():
    if not session.get("access_token"):
        return jsonify({"error": "Unauthorized"}), 401
    raw = request.args.get("symbols", "")
    symbols = [s.strip() for s in raw.split(",") if s.strip()]
    prices: Dict[str, Optional[float]] = {}
    for symbol in symbols:
        sym = symbol.strip()
        prices[sym] = _quote_price_fast_preferred(sym)
    return jsonify(prices)


@app.route("/api/add-stock", methods=["POST"])
def api_add_stock():
    if not session.get("access_token"):
        return jsonify({"error": "Unauthorized"}), 401
    token = session["access_token"]
    uid = session.get("user_id")
    if not uid:
        return jsonify({"error": "Missing user id"}), 400
    data = request.get_json(force=True, silent=True) or {}
    market = (data.get("market") or "NSE/BSE").strip()
    currency = (data.get("currency") or "INR").strip().upper()
    symbol = normalize_stock_symbol(data.get("symbol") or "", market)
    try:
        shares = float(data.get("shares"))
        avg_price = float(data.get("avg_price"))
    except (TypeError, ValueError):
        return jsonify({"error": "shares and avg_price must be numbers"}), 400
    if not symbol:
        return jsonify({"error": "symbol is required"}), 400
    if shares <= 0 or avg_price <= 0:
        return jsonify({"error": "shares and avg_price must be positive"}), 400
    buy_raw = (data.get("buy_date") or "").strip()
    if buy_raw:
        try:
            buy_date = date.fromisoformat(buy_raw[:10]).isoformat()
        except ValueError:
            return jsonify({"error": "Invalid buy_date; use YYYY-MM-DD"}), 400
    else:
        buy_date = date.today().isoformat()
    if not _supabase_base_url():
        return jsonify({"error": "SUPABASE_URL is not configured"}), 500
    row = {
        "user_id": str(uid),
        "symbol": symbol,
        "shares": shares,
        "avg_price": avg_price,
        "buy_date": buy_date,
        "buy_price": avg_price,
        "market": market,
        "currency": currency,
    }
    r = requests.post(
        f"{_rest_v1_url()}/portfolios",
        headers={**_user_jwt_headers(token), "Prefer": "return=minimal"},
        json=row,
        timeout=25,
    )
    if not r.ok:
        return jsonify({"error": _rest_error_message(r)}), 400
    return jsonify({"ok": True})


@app.route("/api/exit-trade", methods=["POST"])
def api_exit_trade():
    if not session.get("access_token"):
        return jsonify({"error": "Unauthorized"}), 401
    token = session["access_token"]
    uid = session.get("user_id")
    if not uid:
        return jsonify({"error": "Missing user id"}), 400
    data = request.get_json(force=True, silent=True) or {}
    record_id = data.get("id")
    if not record_id:
        return jsonify({"error": "id is required"}), 400
    try:
        exit_price = float(data.get("exit_price"))
    except (TypeError, ValueError):
        return jsonify({"error": "exit_price must be a number"}), 400
    exit_raw = (data.get("exit_date") or "").strip()
    if exit_raw:
        try:
            exit_date = date.fromisoformat(exit_raw[:10]).isoformat()
        except ValueError:
            return jsonify({"error": "Invalid exit_date; use YYYY-MM-DD"}), 400
    else:
        return jsonify({"error": "exit_date is required"}), 400
    if not _supabase_base_url():
        return jsonify({"error": "SUPABASE_URL is not configured"}), 500
    r = requests.get(
        f"{_rest_v1_url()}/portfolios",
        headers=_user_jwt_headers(token),
        params={"id": f"eq.{record_id}", "user_id": f"eq.{uid}", "select": "*"},
        timeout=25,
    )
    if not r.ok:
        return jsonify({"error": _rest_error_message(r)}), 400
    rows = r.json()
    if not isinstance(rows, list) or not rows:
        return jsonify({"error": "Record not found"}), 404
    row = rows[0]
    shares = float(row.get("shares") or 0)
    avg_price = float(row.get("avg_price") or 0)
    final_pnl = round((exit_price - avg_price) * shares, 2)
    update = {
        "status": "closed",
        "exit_price": exit_price,
        "exit_date": exit_date,
        "final_pnl": final_pnl,
    }
    r = requests.patch(
        f"{_rest_v1_url()}/portfolios?id=eq.{record_id}&user_id=eq.{uid}",
        headers={**_user_jwt_headers(token), "Prefer": "return=minimal"},
        json=update,
        timeout=25,
    )
    if not r.ok:
        return jsonify({"error": _rest_error_message(r)}), 400
    return jsonify({"ok": True})


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = (request.form.get("email") or "").strip()
    password = request.form.get("password") or ""
    if not email or not password:
        flash("Email and password are required.", "error")
        return redirect(url_for("login"))

    base = _supabase_base_url()
    key = _supabase_anon_key()
    if not base or not key:
        flash("Server missing SUPABASE_URL or SUPABASE_KEY.", "error")
        return redirect(url_for("login"))

    resp = requests.post(
        _auth_url("/auth/v1/token?grant_type=password"),
        headers=_auth_headers(),
        json={
            "grant_type": "password",
            "email": email,
            "password": password,
        },
        timeout=20,
    )

    if not resp.ok:
        flash(_auth_error_message(resp), "error")
        return redirect(url_for("login"))

    payload = resp.json()
    access_token = payload.get("access_token")
    refresh_token = payload.get("refresh_token")
    user = payload.get("user")
    if not access_token:
        flash("Sign-in succeeded but no access token was returned.", "error")
        return redirect(url_for("login"))

    _apply_auth_session(
        access_token,
        refresh_token,
        user if isinstance(user, dict) else {},
    )

    session.pop("_flashes", None)
    return redirect(url_for("dashboard"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    full_name = (
        request.form.get("full_name") or request.form.get("name") or ""
    ).strip()
    email = (request.form.get("email") or "").strip()
    password = request.form.get("password") or ""
    if not full_name or not email or not password:
        flash("Please fill in full name, email, and password.", "error")
        return redirect(url_for("signup"))

    base = _supabase_base_url()
    key = _supabase_anon_key()
    if not base or not key:
        flash("Server missing SUPABASE_URL or SUPABASE_KEY.", "error")
        return redirect(url_for("signup"))

    signup_resp = requests.post(
        _auth_url("/auth/v1/signup"),
        headers=_auth_headers(),
        json={
            "email": email,
            "password": password,
            "data": {"full_name": full_name},
        },
        timeout=20,
    )

    if not signup_resp.ok:
        flash(_auth_error_message(signup_resp), "error")
        return redirect(url_for("signup"))

    payload = signup_resp.json()
    sess = payload.get("session")
    user = payload.get("user")
    if isinstance(sess, dict) and sess.get("access_token"):
        _apply_auth_session(
            sess["access_token"],
            sess.get("refresh_token"),
            user if isinstance(user, dict) else {},
        )

    if session.get("user_id"):
        session.pop("_flashes", None)
        return redirect(url_for("profile_setup"))
    flash("Account created. Confirm your email if required, then sign in.", "success")
    return redirect(url_for("login"))


@app.route("/profile-setup", methods=["GET", "POST"], strict_slashes=False)
def profile_setup():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        session["name"] = request.form.get("display_name", session.get("name", ""))
        session["currency"] = request.form.get("currency", "INR")
        session["market"] = request.form.get("market", "NSE/BSE")
        session["timezone"] = request.form.get("timezone", "Asia/Kolkata")
        photo = request.form.get("photo_base64", "")
        if photo and len(photo) > 100:
            session["photo"] = photo
        session.modified = True
        return redirect("/profile")

    name_val = session.get("name", "")
    return render_template(
        "profile_setup.html",
        name=name_val,
        currency=session.get("currency", "INR"),
        market=session.get("market", "NSE/BSE"),
        timezone=session.get("timezone", "Asia/Kolkata"),
        photo=session.get("photo", ""),
        timezones=TIMEZONES,
        currencies=CURRENCIES,
        markets=MARKETS,
        initials=_initials_from_name(name_val),
    )


def _dashboard_user_context():
    token = session.get("access_token")
    user = _fetch_supabase_user(token) if token else None
    meta = (user or {}).get("user_metadata") or {}
    username = (session.get("name") or "").strip()
    if not username:
        username = (meta.get("display_name") or meta.get("full_name") or "").strip()
    if not username:
        email = session.get("email") or ""
        username = email.split("@")[0] if email and "@" in email else "Investor"
    initials = _initials_from_name(username)
    avatar_url = (session.get("photo") or meta.get("photo_base64") or meta.get("avatar_url") or "").strip()
    hour = datetime.now().hour
    if hour < 12:
        greeting = "Good morning"
    elif hour < 17:
        greeting = "Good afternoon"
    else:
        greeting = "Good evening"
    today_str = datetime.now().strftime("%A, %d %B %Y")
    return {
        "greeting": greeting,
        "username": username,
        "today_str": today_str,
        "initials": initials,
        "avatar_url": avatar_url,
    }


@app.route("/dashboard")
def dashboard():
    ctx = _dashboard_user_context()
    uid = session.get("user_id") or ""
    pm = _portfolio_metrics_for_user(session["access_token"], uid)
    ctx.update(
        portfolio_total_display=pm["current_display"],
        portfolio_stocks_count=pm["stocks_count"],
        portfolio_return_pct=pm.get("return_pct"),
        portfolio_today_gain=pm["today_gain_display"],
        portfolio_return_positive=(pm.get("return_pct") is not None and pm["return_pct"] >= 0),
        portfolio_today_positive=(pm.get("today_pnl") is not None and pm["today_pnl"] >= 0),
        profit_booked_display=pm.get("profit_booked_display", "₹0.00"),
        profit_booked_positive=(pm.get("profit_booked", 0) >= 0),
    )
    return render_template("dashboard.html", **ctx)


@app.route("/portfolio")
def portfolio():
    token = session["access_token"]
    uid = session.get("user_id") or ""
    rows = _fetch_portfolios_for_user(token, uid)
    active_enriched, metrics = _enrich_portfolio_rows(rows)
    closed_enriched = _enrich_closed_rows(rows)
    holdings_poll: List[Dict[str, Any]] = []
    active_rows = [r for r in rows if (r.get("status") or "active") != "closed"]
    for r, h in zip(active_rows, active_enriched):
        buy_px = r.get("buy_price")
        if buy_px is None:
            buy_px = r.get("avg_price")
        holdings_poll.append(
            {
                "symbol": (r.get("symbol") or "").strip(),
                "shares": float(r.get("shares") or 0),
                "buy": float(buy_px or 0),
                "currency": h.get("currency") or "USD",
                "price_ok": bool(h.get("price_ok")),
            }
        )
    return render_template(
        "portfolio.html",
        active_holdings=active_enriched,
        closed_holdings=closed_enriched,
        holdings_poll=holdings_poll,
        invested_display=metrics["invested_display"],
        current_display=metrics["current_display"],
        current_is_up=metrics["current_is_up"],
        summary_gain_line=metrics.get("summary_gain_line", ""),
        has_active=len(active_enriched) > 0,
        has_closed=len(closed_enriched) > 0,
    )


@app.route("/charts")
def charts():
    return render_template("charts.html")


@app.route("/api/finnhub-chart")
def finnhub_chart():
    if not session.get("access_token"):
        return jsonify({"error": "Unauthorized"}), 401
    symbol = request.args.get("symbol", "AAPL")
    resolution = request.args.get("resolution", "D")
    finnhub_key = os.getenv("FINNHUB_API_KEY", "")

    to_time = int(time.time())
    from_time = to_time - (365 * 24 * 60 * 60)

    # Auto detect market type from symbol
    if ":" in symbol and any(x in symbol for x in ["BINANCE", "COINBASE", "KRAKEN"]):
        url = (
            f"https://finnhub.io/api/v1/crypto/candle"
            f"?symbol={symbol}&resolution={resolution}&from={from_time}&to={to_time}&token={finnhub_key}"
        )
    elif ":" in symbol and any(x in symbol for x in ["OANDA", "FOREX", "FX"]):
        url = (
            f"https://finnhub.io/api/v1/forex/candle"
            f"?symbol={symbol}&resolution={resolution}&from={from_time}&to={to_time}&token={finnhub_key}"
        )
    else:
        url = (
            f"https://finnhub.io/api/v1/stock/candle"
            f"?symbol={symbol}&resolution={resolution}&from={from_time}&to={to_time}&token={finnhub_key}"
        )

    print(f"Fetching: {url}")
    response = requests.get(url, timeout=20)
    data = response.json()
    print(f"Response: {data}")

    if data.get("s") == "ok":
        dates = [datetime.fromtimestamp(t).strftime("%Y-%m-%d") for t in data["t"]]
        return jsonify({
            "dates": dates,
            "open": data["o"],
            "high": data["h"],
            "low": data["l"],
            "close": data["c"],
            "volume": data["v"],
            "symbol": symbol,
        })
    return jsonify({"error": f"No data found for {symbol}", "raw": data}), 404


@app.route("/ai-analysis")
def ai_analysis():
    if not session.get("access_token"):
        return redirect(url_for("login"))
    token = session["access_token"]
    uid = session.get("user_id") or ""
    rows = _fetch_portfolios_for_user(token, uid)
    active_rows = [r for r in rows if (r.get("status") or "active") != "closed"]

    stocks_data = []
    total_invested = 0.0
    total_current = 0.0

    for r in active_rows:
        sym = (r.get("symbol") or "").strip().upper()
        shares = float(r.get("shares") or 0)
        buy_px = r.get("buy_price")
        if buy_px is None:
            buy_px = r.get("avg_price")
        avg_price = float(buy_px or 0)
        live_price = get_live_price(sym)

        if live_price:
            current_value = round(shares * live_price, 2)
            invested_value = round(shares * avg_price, 2)
            gain_loss_amount = round(current_value - invested_value, 2)
            gain_loss_pct = round(((live_price - avg_price) / avg_price) * 100, 2) if avg_price else 0.0
        else:
            current_value = None
            invested_value = round(shares * avg_price, 2)
            gain_loss_amount = None
            gain_loss_pct = None

        total_invested += shares * avg_price
        if current_value:
            total_current += current_value

        stocks_data.append({
            "id": r.get("id"),
            "symbol": sym,
            "shares": shares,
            "avg_price": avg_price,
            "live_price": live_price,
            "current_value": current_value,
            "invested_value": invested_value,
            "gain_loss_amount": gain_loss_amount,
            "gain_loss_pct": gain_loss_pct,
            "market": r.get("market") or "NSE/BSE",
            "currency": (r.get("currency") or "").strip().upper() or "INR",
        })

    total_invested = round(total_invested, 2)
    total_current = round(total_current, 2)
    total_gain_loss = round(total_current - total_invested, 2)
    total_gain_loss_pct = round(((total_current - total_invested) / total_invested * 100), 2) if total_invested > 0 else 0.0

    # Calculate portfolio percentages
    for s in stocks_data:
        if s["current_value"] and total_current > 0:
            s["portfolio_pct"] = round((s["current_value"] / total_current) * 100, 2)
        else:
            s["portfolio_pct"] = 0.0

    return render_template(
        "ai_analysis.html",
        stocks=stocks_data,
        total_invested=total_invested,
        total_current=total_current,
        total_gain_loss=total_gain_loss,
        total_gain_loss_pct=total_gain_loss_pct,
        has_stocks=len(stocks_data) > 0,
    )


@app.route("/api/analyse-portfolio", methods=["POST"])
def analyse_portfolio():
    if not session.get("access_token"):
        return jsonify({"error": "Not logged in"}), 401
    token = session["access_token"]
    uid = session.get("user_id") or ""
    if not uid:
        return jsonify({"error": "Not logged in"}), 401

    groq_key = (os.getenv("GROQ_API_KEY") or "").strip()
    if not groq_key:
        return jsonify({"error": "GROQ_API_KEY not configured"}), 500

    ai_text = ""
    try:
        rows = _fetch_portfolios_for_user(token, uid)
        active_rows = [r for r in rows if (r.get("status") or "active") != "closed"]
        if not active_rows:
            return jsonify(
                {"error": "No stocks found in portfolio. Please add stocks first."}
            )

        total_invested = 0.0
        total_current = 0.0
        portfolio_lines: List[str] = []

        for stock in active_rows:
            symbol = (stock.get("symbol") or "").strip().upper()
            shares = float(stock.get("shares") or 0)
            buy_px = stock.get("buy_price")
            if buy_px is None:
                buy_px = stock.get("avg_price")
            avg_price = float(buy_px or 0)
            live_price = get_live_price(symbol)

            if live_price and live_price > 0:
                current_value = round(shares * live_price, 2)
                invested_value = round(shares * avg_price, 2)
                gain_pct = (
                    round(((live_price - avg_price) / avg_price) * 100, 2)
                    if avg_price
                    else 0.0
                )
                total_invested += invested_value
                total_current += current_value
                portfolio_lines.append(
                    f"- {symbol}: {shares} shares, bought at {avg_price}, "
                    f"current price {live_price}, gain/loss {gain_pct}%, "
                    f"market: {stock.get('market', 'NSE/BSE')}"
                )

        if not portfolio_lines:
            return jsonify(
                {"error": "Could not fetch live prices for your stocks. Try again."}
            )

        total_gain_pct = (
            round(((total_current - total_invested) / total_invested * 100), 2)
            if total_invested > 0
            else 0.0
        )
        portfolio_text = "\n".join(portfolio_lines)

        prompt = f"""You are a world-class stock market analyst with 20 years experience in Indian and global markets. You have deep knowledge of current market news, sector trends, and stock movements.

Portfolio data:
{portfolio_text}

Total invested: {total_invested}
Total current value: {total_current}
Overall gain/loss: {total_gain_pct}%

You MUST respond with ONLY valid JSON. No markdown, no backticks, no text outside JSON.

Respond with exactly this JSON structure:
{{
    "risk_level": "HIGH or MEDIUM or LOW",
    "diversification": "GOOD or FAIR or POOR",
    "overall_health": "GOOD or FAIR or POOR",
    "summary": "2 sentence expert summary of portfolio situation",
    "suggestions": [
        "Specific actionable suggestion 1 about current holdings",
        "Specific actionable suggestion 2 about risk management",
        "Specific actionable suggestion 3 about diversification"
    ],
    "hold_recommendations": [
        {{
            "symbol": "exact symbol from portfolio",
            "action": "HOLD or SELL or ADD MORE",
            "hold_until": "specific timeframe like 3-6 months or Q3 2026",
            "target_price": "estimated target price",
            "stop_loss": "recommended stop loss price",
            "reasoning": "detailed reason based on technicals and fundamentals"
        }}
    ],
    "news_based_opportunities": [
        {{
            "symbol": "stock symbol",
            "news_catalyst": "specific news or event driving this stock",
            "expected_impact": "POSITIVE or NEGATIVE",
            "potential_gain": "estimated % gain possible",
            "timeframe": "how long this opportunity lasts",
            "reason": "detailed explanation of why this news matters"
        }},
        {{
            "symbol": "another stock",
            "news_catalyst": "specific news or event",
            "expected_impact": "POSITIVE or NEGATIVE",
            "potential_gain": "estimated % gain possible",
            "timeframe": "timeframe",
            "reason": "detailed explanation"
        }},
        {{
            "symbol": "another stock",
            "news_catalyst": "specific news or event",
            "expected_impact": "POSITIVE or NEGATIVE",
            "potential_gain": "estimated % gain possible",
            "timeframe": "timeframe",
            "reason": "detailed explanation"
        }}
    ],
    "stocks_to_watch": [
        {{
            "symbol": "HDFCBANK.NS",
            "reason": "Why this stock is worth watching now"
        }},
        {{
            "symbol": "INFY.NS",
            "reason": "Why this stock is worth watching now"
        }},
        {{
            "symbol": "BTC-USD",
            "reason": "Why this asset is worth watching now"
        }}
    ],
    "sectors_to_explore": [
        {{
            "sector": "Banking and Finance",
            "reason": "Why this sector looks good now"
        }},
        {{
            "sector": "Technology",
            "reason": "Why this sector looks good now"
        }},
        {{
            "sector": "Pharma",
            "reason": "Why this sector looks good now"
        }}
    ],
    "market_outlook": "2 sentence view on Indian market and global markets right now",
    "best_performing": "symbol of best stock in portfolio",
    "worst_performing": "symbol of worst stock in portfolio",
    "immediate_action": "One most important thing the investor should do right now"
}}"""

        groq_response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {groq_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 4096,
            },
            timeout=30,
        )
        groq_data = groq_response.json()
        print("Groq response:", groq_data)

        if not groq_response.ok:
            err = groq_data.get("error", {}) if isinstance(groq_data, dict) else {}
            msg = (
                err.get("message", groq_response.text)
                if isinstance(err, dict)
                else str(groq_data)
            )
            return jsonify({"error": f"Groq API error: {msg}"}), 502

        choices = groq_data.get("choices") or []
        if not choices:
            return jsonify({"error": "No analysis returned", "raw": groq_data}), 502
        assistant_message = choices[0].get("message") or {}
        ai_text = (assistant_message.get("content") or "").strip()
        if not ai_text:
            return jsonify({"error": "Empty Groq content", "raw": groq_data}), 502

        if "```" in ai_text:
            chunks = ai_text.split("```")
            ai_text = chunks[1] if len(chunks) > 1 else ai_text
            ai_text = ai_text.strip()
            if ai_text.lower().startswith("json"):
                ai_text = ai_text[4:].strip()

        result = json.loads(ai_text)
        return jsonify(result)

    except json.JSONDecodeError as e:
        print(f"AI analysis JSON error: {e}")
        return jsonify(
            {"error": f"Analysis failed: {str(e)}", "raw": ai_text}
        ), 502
    except Exception as e:
        print(f"AI analysis error: {e}")
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


@app.route("/profile")
def profile():
    if not session.get("access_token"):
        flash("Please sign in.", "error")
        return redirect(url_for("login"))

    token = session["access_token"]
    user = _fetch_supabase_user(token)
    if not user:
        flash("Could not load your profile. Please sign in again.", "error")
        session.clear()
        return redirect(url_for("login"))

    meta = user.get("user_metadata") or {}
    name = (
        session.get("name")
        or meta.get("display_name")
        or meta.get("full_name")
        or session.get("email", "").split("@")[0]
        or "Investor"
    )
    initials = _initials_from_name(name)
    photo = session.get("photo") or meta.get("photo_base64") or ""
    email = session.get("email") or user.get("email") or ""
    currency = session.get("currency") or meta.get("currency") or "INR"
    market = session.get("market") or meta.get("preferred_market") or "NSE/BSE"
    created_at = user.get("created_at") or ""
    member_since = ""
    if created_at:
        try:
            member_since = datetime.fromisoformat(created_at.replace("Z", "+00:00")).strftime("%d %b %Y")
        except Exception:
            member_since = created_at[:10] if len(created_at) >= 10 else created_at

    return render_template(
        "profile.html",
        name=name,
        initials=initials,
        photo=photo,
        email=email,
        currency=currency,
        market=market,
        member_since=member_since,
    )


@oauth_authorized.connect_via(google_bp)
def google_logged_in(blueprint, token):
    if not token:
        flash("Google sign-in was not completed.", "error")
        return redirect(url_for("login"))

    resp = blueprint.session.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Could not fetch Google profile.", "error")
        return redirect(url_for("login"))

    user_info = resp.json()
    email = user_info.get("email", "")
    name = user_info.get("name", "")
    google_id = user_info.get("id", "")
    picture = user_info.get("picture", "")

    if not name and email and "@" in email:
        name = email.split("@")[0]
    if not name:
        name = "Investor"

    session["email"] = email
    session["name"] = name
    session["user_id"] = f"google_{google_id}" if google_id else email
    session["access_token"] = f"google_oauth_{google_id}"
    if picture:
        session["photo"] = picture

    session.pop("_flashes", None)
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
