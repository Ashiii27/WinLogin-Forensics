"""Phase 5 — Feature engineering tests."""

from __future__ import annotations

from src.analysis.feature_engineer import FEATURE_COLUMNS, FeatureEngineer, geolocate_ip
from src.parsers.evtx_parser import EvtxParser
from src.parsers.session_correlator import SessionCorrelator


def test_impossible_travel_flagged():
    events = EvtxParser().parse_records(
        [
            {
                "EventID": 4624,
                "TimeCreated": "2026-08-12T10:00:00Z",
                "TargetUserName": "alice",
                "TargetLogonId": "0x1",
                "LogonType": 10,
                "IpAddress": "198.51.100.20",  # New York
                "WorkstationName": "WS-NY",
            },
            {
                "EventID": 4634,
                "TimeCreated": "2026-08-12T10:05:00Z",
                "TargetUserName": "alice",
                "TargetLogonId": "0x1",
                "LogonType": 10,
                "IpAddress": "198.51.100.20",
                "WorkstationName": "WS-NY",
            },
            {
                "EventID": 4624,
                "TimeCreated": "2026-08-12T10:30:00Z",
                "TargetUserName": "alice",
                "TargetLogonId": "0x2",
                "LogonType": 10,
                "IpAddress": "203.0.113.10",  # Tokyo
                "WorkstationName": "WS-TYO",
            },
        ]
    )
    sessions = SessionCorrelator(events).correlate()
    feats = FeatureEngineer(sessions, events).transform()
    assert not feats.empty
    for col in FEATURE_COLUMNS:
        assert col in feats.columns
    assert int(feats["impossible_travel_flag"].max()) == 1
    flagged = feats[feats["impossible_travel_flag"] == 1].iloc[0]
    assert flagged["distance_km_from_last_logon"] > 900
    assert flagged["ip_geolocation_city"] == "Tokyo"


def test_temporal_and_auth_features():
    events = EvtxParser().parse_records(
        [
            {
                "EventID": 4625,
                "TimeCreated": "2026-08-12T13:10:00Z",
                "TargetUserName": "bob",
                "IpAddress": "10.0.0.9",
                "TargetLogonId": "0x0",
                "LogonType": 3,
                "WorkstationName": "WS",
            },
            {
                "EventID": 4625,
                "TimeCreated": "2026-08-12T13:12:00Z",
                "TargetUserName": "carol",
                "IpAddress": "10.0.0.9",
                "TargetLogonId": "0x0",
                "LogonType": 3,
                "WorkstationName": "WS",
            },
            {
                "EventID": 4624,
                "TimeCreated": "2026-08-12T13:20:00Z",
                "TargetUserName": "bob",
                "TargetLogonId": "0xbb",
                "LogonType": 3,
                "IpAddress": "10.0.0.9",
                "WorkstationName": "WS",
            },
            {
                "EventID": 4672,
                "TimeCreated": "2026-08-12T13:20:01Z",
                "TargetUserName": "bob",
                "TargetLogonId": "0xbb",
            },
        ]
    )
    sessions = SessionCorrelator(events).correlate()
    feats = FeatureEngineer(sessions, events).transform()
    row = feats.iloc[0]
    assert row["hour_of_day"] == 13
    assert row["is_weekend"] in (0, 1)
    assert row["is_business_hours"] == 1
    assert row["logon_type"] == 3
    assert row["failed_logon_count_last_1h"] >= 1
    assert row["unique_accounts_per_source_ip_last_1h"] >= 2
    assert row["has_special_privileges"] == 1


def test_geolocate_private_and_known():
    assert geolocate_ip("10.1.2.3")[0] == "Private"
    assert geolocate_ip("198.51.100.20")[1] == "New York"
