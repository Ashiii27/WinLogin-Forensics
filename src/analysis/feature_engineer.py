"""
WinLogin Forensics - Feature engineering
========================================
Computes per-session behavioural features across temporal, authentication
pattern, privilege, and geographic groups — including impossible-travel
detection via haversine distance.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from ..utils.helpers import haversine_km, safe_int, safe_str
from ..utils.time_utils import is_business_hours, normalize_to_utc, time_delta_seconds


# Deterministic offline geolocation for public/test IPs.
# Private RFC1918 ranges resolve to (None, None) so they never trip travel.
IP_GEO: Dict[str, Tuple[str, str, float, float]] = {
    "8.8.8.8": ("US", "Mountain View", 37.386, -122.0838),
    "1.1.1.1": ("AU", "Sydney", -33.8688, 151.2093),
    "185.220.101.5": ("DE", "Frankfurt", 50.1109, 8.6821),
    "198.51.100.20": ("US", "New York", 40.7128, -74.0060),
    "203.0.113.10": ("JP", "Tokyo", 35.6762, 139.6503),
    "203.0.113.50": ("IN", "Mumbai", 19.0760, 72.8777),
    "93.184.216.34": ("US", "Boston", 42.3601, -71.0589),
    "51.15.0.1": ("FR", "Paris", 48.8566, 2.3522),
}

IMPOSSIBLE_TRAVEL_KMH = 900.0

FEATURE_COLUMNS = [
    "hour_of_day",
    "day_of_week",
    "is_weekend",
    "is_business_hours",
    "time_since_last_logon",
    "logon_type",
    "failed_logon_count_last_1h",
    "unique_accounts_per_source_ip_last_1h",
    "has_special_privileges",
    "privilege_escalation_delta",
    "ip_geolocation_country",
    "ip_geolocation_city",
    "distance_km_from_last_logon",
    "impossible_travel_flag",
]


def geolocate_ip(ip: str) -> Tuple[str, str, Optional[float], Optional[float]]:
    """
    Look up a coarse geolocation for ``ip``.

    Parameters
    ----------
    ip : str
        IPv4 address.

    Returns
    -------
    tuple
        ``(country, city, lat, lon)``. Private/unknown IPs return
        ``("Private", "RFC1918", None, None)`` or ``("Unknown", "-", None, None)``.
    """
    text = safe_str(ip)
    if text in {"-", "", "None", "::1", "127.0.0.1"}:
        return "Local", "localhost", None, None
    if text in IP_GEO:
        country, city, lat, lon = IP_GEO[text]
        return country, city, lat, lon
    # RFC1918
    if text.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.")):
        return "Private", "RFC1918", None, None
    return "Unknown", "-", None, None


class FeatureEngineer:
    """
    Build a numeric/categorical feature frame aligned with sessions.

    Parameters
    ----------
    sessions : pd.DataFrame
        Correlated sessions.
    events : pd.DataFrame, optional
        Raw events (used for failed-logon / unique-account counts).
    impossible_kmh : float
        Speed threshold for the impossible-travel flag.
    """

    def __init__(
        self,
        sessions: pd.DataFrame,
        events: Optional[pd.DataFrame] = None,
        impossible_kmh: float = IMPOSSIBLE_TRAVEL_KMH,
    ):
        self.sessions = sessions.copy() if sessions is not None else pd.DataFrame()
        self.events = events.copy() if events is not None and not events.empty else pd.DataFrame()
        self.impossible_kmh = float(impossible_kmh)

    def transform(self) -> pd.DataFrame:
        """
        Compute the full feature matrix (one row per session).

        Returns
        -------
        pd.DataFrame
            Session identifiers plus ``FEATURE_COLUMNS``.
        """
        if self.sessions is None or self.sessions.empty:
            return pd.DataFrame(columns=["SessionID"] + FEATURE_COLUMNS)

        work = self.sessions.copy()
        work["LogonTime"] = pd.to_datetime(work["LogonTime"], utc=True, errors="coerce")
        work = work.sort_values(["Username", "LogonTime"]).reset_index(drop=True)

        rows: List[Dict[str, Any]] = []
        last_by_user: Dict[str, Dict[str, Any]] = {}

        for _, sess in work.iterrows():
            ts = sess.get("LogonTime")
            user = safe_str(sess.get("Username")).lower()
            ip = safe_str(sess.get("IpAddress"))
            hour = int(ts.hour) if pd.notna(ts) else -1
            dow = int(ts.dayofweek) if pd.notna(ts) else -1
            weekend = bool(dow >= 5) if dow >= 0 else False
            business = bool(is_business_hours(ts)) if pd.notna(ts) else False

            prev = last_by_user.get(user)
            time_since = 0.0
            if prev is not None and pd.notna(ts) and pd.notna(prev["ts"]):
                time_since = max(0.0, time_delta_seconds(prev["ts"], ts))

            country, city, lat, lon = geolocate_ip(ip)
            distance = 0.0
            impossible = False
            if prev is not None and lat is not None and prev.get("lat") is not None and time_since > 0:
                distance = haversine_km(prev["lat"], prev["lon"], lat, lon)
                hours = time_since / 3600.0
                speed = distance / hours if hours > 0 else 0.0
                if speed > self.impossible_kmh:
                    impossible = True

            failed_1h, unique_accts = self._auth_window_stats(ip, ts)

            has_priv = bool(sess.get("HasSpecialPrivileges", False))
            prev_priv = bool(prev["priv"]) if prev is not None else False
            if prev is None:
                priv_delta = int(has_priv)
            else:
                priv_delta = int(has_priv) - int(prev_priv)

            rows.append(
                {
                    "SessionID": sess.get("SessionID"),
                    "Username": sess.get("Username"),
                    "IpAddress": ip,
                    "WorkstationName": sess.get("WorkstationName"),
                    "hour_of_day": hour,
                    "day_of_week": dow,
                    "is_weekend": int(weekend),
                    "is_business_hours": int(business),
                    "time_since_last_logon": float(time_since),
                    "logon_type": safe_int(sess.get("LogonType"), default=-1),
                    "failed_logon_count_last_1h": int(failed_1h),
                    "unique_accounts_per_source_ip_last_1h": int(unique_accts),
                    "has_special_privileges": int(has_priv),
                    "privilege_escalation_delta": int(priv_delta),
                    "ip_geolocation_country": country,
                    "ip_geolocation_city": city,
                    "distance_km_from_last_logon": float(distance),
                    "impossible_travel_flag": int(impossible),
                }
            )
            last_by_user[user] = {"ts": ts, "lat": lat, "lon": lon, "priv": has_priv, "ip": ip}

        return pd.DataFrame(rows)

    def _auth_window_stats(self, ip: str, ts) -> Tuple[int, int]:
        if self.events.empty or pd.isna(ts) or ip in {"-", "", "None"}:
            return 0, 0
        if "IpAddress" not in self.events.columns or "TimeCreated" not in self.events.columns:
            return 0, 0
        ev = self.events.copy()
        ev["TimeCreated"] = pd.to_datetime(ev["TimeCreated"], utc=True, errors="coerce")
        window_start = ts - pd.Timedelta(hours=1)
        mask = (ev["IpAddress"].astype(str) == ip) & (ev["TimeCreated"] >= window_start) & (ev["TimeCreated"] <= ts)
        subset = ev.loc[mask]
        failed = subset[subset["EventID"].astype(int) == 4625] if "EventID" in subset.columns else subset.iloc[0:0]
        users = subset.get("TargetUserName", pd.Series(dtype=str)).dropna().astype(str)
        users = {u for u in users if u not in {"-", ""}}
        return int(len(failed)), int(len(users))


def engineer_features(
    sessions: pd.DataFrame,
    events: Optional[pd.DataFrame] = None,
    **kwargs: Any,
) -> pd.DataFrame:
    """
    Convenience wrapper around :class:`FeatureEngineer`.

    Parameters
    ----------
    sessions, events
        Input frames.
    **kwargs
        Forwarded to the engineer.

    Returns
    -------
    pd.DataFrame
        Feature matrix.
    """
    return FeatureEngineer(sessions, events, **kwargs).transform()
