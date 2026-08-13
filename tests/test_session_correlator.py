"""Phase 1 — Session correlator tests."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from src.parsers.evtx_parser import EvtxParser
from src.parsers.session_correlator import SessionCorrelator, correlate_sessions


def _events(rows):
    return EvtxParser().parse_records(rows)


def test_match_on_target_logon_id():
    df = _events(
        [
            {
                "EventID": 4624,
                "TimeCreated": "2026-08-12T09:00:00Z",
                "TargetUserName": "alice",
                "TargetLogonId": "0xabc",
                "LogonType": 2,
                "IpAddress": "10.0.0.8",
                "WorkstationName": "WS1",
                "TargetDomainName": "CORP",
            },
            {
                "EventID": 4634,
                "TimeCreated": "2026-08-12T10:30:00Z",
                "TargetUserName": "alice",
                "TargetLogonId": "0xabc",
                "LogonType": 2,
                "WorkstationName": "WS1",
            },
        ]
    )
    sessions = SessionCorrelator(df).correlate()
    assert len(sessions) == 1
    row = sessions.iloc[0]
    assert row["TargetLogonId"] == "0xabc"
    assert row["Status"] == "closed"
    assert row["DurationSeconds"] == pytest.approx(5400.0)
    assert row["DurationSeconds"] >= 0


def test_user_initiated_logoff_4647():
    df = _events(
        [
            {
                "EventID": 4624,
                "TimeCreated": "2026-08-12T09:00:00Z",
                "TargetUserName": "bob",
                "TargetLogonId": "0x99",
                "LogonType": 2,
                "WorkstationName": "WS2",
            },
            {
                "EventID": 4647,
                "TimeCreated": "2026-08-12T09:05:00Z",
                "TargetUserName": "bob",
                "TargetLogonId": "0x99",
                "WorkstationName": "WS2",
            },
        ]
    )
    sessions = correlate_sessions(df)
    assert sessions.iloc[0]["Status"] == "closed"
    assert int(sessions.iloc[0]["EndEventID"]) == 4647


def test_orphaned_session_flagged():
    df = _events(
        [
            {
                "EventID": 4624,
                "TimeCreated": "2026-08-12T09:00:00Z",
                "TargetUserName": "carol",
                "TargetLogonId": "0xorphan",
                "LogonType": 10,
                "WorkstationName": "WS3",
            }
        ]
    )
    sessions = SessionCorrelator(df).correlate()
    assert len(sessions) == 1
    assert sessions.iloc[0]["Status"] == "orphaned"
    assert sessions.iloc[0]["DurationSeconds"] >= 0


def test_duration_never_negative_when_clock_skew():
    df = _events(
        [
            {
                "EventID": 4624,
                "TimeCreated": "2026-08-12T12:00:00Z",
                "TargetUserName": "dave",
                "TargetLogonId": "0xskew",
                "LogonType": 2,
                "WorkstationName": "WS4",
            },
            {
                "EventID": 4634,
                "TimeCreated": "2026-08-12T11:00:00Z",  # earlier than logon
                "TargetUserName": "dave",
                "TargetLogonId": "0xskew",
                "LogonType": 2,
                "WorkstationName": "WS4",
            },
        ]
    )
    sessions = SessionCorrelator(df).correlate()
    assert (sessions["DurationSeconds"] >= 0).all()


def test_session_overlap_detected():
    df = _events(
        [
            {
                "EventID": 4624,
                "TimeCreated": "2026-08-12T09:00:00Z",
                "TargetUserName": "erin",
                "TargetLogonId": "0xaaa",
                "LogonType": 2,
                "WorkstationName": "WS5",
            },
            {
                "EventID": 4624,
                "TimeCreated": "2026-08-12T09:10:00Z",
                "TargetUserName": "erin",
                "TargetLogonId": "0xbbb",
                "LogonType": 3,
                "WorkstationName": "WS5",
            },
            {
                "EventID": 4634,
                "TimeCreated": "2026-08-12T10:00:00Z",
                "TargetUserName": "erin",
                "TargetLogonId": "0xaaa",
                "WorkstationName": "WS5",
            },
            {
                "EventID": 4634,
                "TimeCreated": "2026-08-12T10:20:00Z",
                "TargetUserName": "erin",
                "TargetLogonId": "0xbbb",
                "WorkstationName": "WS5",
            },
        ]
    )
    sessions = SessionCorrelator(df).correlate()
    assert len(sessions) == 2
    assert bool(sessions["OverlapFlag"].any())


def test_special_privileges_attached():
    df = _events(
        [
            {
                "EventID": 4624,
                "TimeCreated": "2026-08-12T09:00:00Z",
                "TargetUserName": "Administrator",
                "TargetLogonId": "0xpriv",
                "LogonType": 10,
                "WorkstationName": "DC01",
            },
            {
                "EventID": 4672,
                "TimeCreated": "2026-08-12T09:00:01Z",
                "TargetUserName": "Administrator",
                "TargetLogonId": "0xpriv",
            },
        ]
    )
    sessions = SessionCorrelator(df).correlate()
    assert bool(sessions.iloc[0]["HasSpecialPrivileges"])
    assert sessions.iloc[0]["Status"] == "orphaned"


def test_incremental_streaming_closes_session():
    corr = SessionCorrelator()
    assert (
        corr.process_event(
            {
                "EventID": 4624,
                "TimeCreated": "2026-08-12T09:00:00Z",
                "TargetUserName": "frank",
                "TargetLogonId": "0xlive",
                "LogonType": 2,
                "WorkstationName": "WS6",
            }
        )
        is None
    )
    assert len(corr.open_sessions) == 1
    assert list(corr.open_sessions.values())[0]["Status"] == "active"
    closed = corr.process_event(
        {
            "EventID": 4634,
            "TimeCreated": "2026-08-12T09:30:00Z",
            "TargetUserName": "frank",
            "TargetLogonId": "0xlive",
        }
    )
    assert closed is not None
    assert closed["Status"] == "closed"
    assert closed["DurationSeconds"] == pytest.approx(1800.0)


def test_empty_events_returns_empty_frame():
    sessions = SessionCorrelator(pd.DataFrame()).correlate()
    assert sessions.empty
