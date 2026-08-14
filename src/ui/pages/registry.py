"""Registry — SAM accounts, Run keys, UserAssist."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from src.ui.components.tables import show_table
from src.ui.theme import inject, require_result


def render() -> None:
    """Render the Registry page."""
    inject()
    result = require_result()
    st.title("Registry artefacts")
    reg = result.registry or {}

    st.subheader("SAM accounts")
    show_table(pd.DataFrame(reg.get("sam") or []), ["RID", "Username", "CreationTime", "LastLogon", "PasswordLastSet", "LoginCount", "Enabled"])

    st.subheader("Run / RunOnce")
    show_table(pd.DataFrame(reg.get("run_keys") or []), ["KeyPath", "ValueName", "Command", "Suspicious"])

    st.subheader("Remote access tools")
    show_table(pd.DataFrame(reg.get("remote_access") or []), ["ToolName", "Category", "Evidence", "Status", "RiskLevel"])

    st.subheader("UserAssist (ROT13 decoded)")
    show_table(pd.DataFrame(reg.get("userassist") or []), ["EncodedPath", "DecodedPath", "RunCount", "LastExecuted", "Suspicious"])
