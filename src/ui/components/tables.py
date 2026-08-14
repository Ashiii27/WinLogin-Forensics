"""Dataframe display helpers."""

from __future__ import annotations

from typing import Optional, Sequence

import pandas as pd
import streamlit as st


def show_table(df: Optional[pd.DataFrame], columns: Optional[Sequence[str]] = None, height: int = 420) -> None:
    """Render a filterable dataframe, silently skipping missing columns."""
    if df is None or df.empty:
        st.caption("No rows.")
        return
    cols = [c for c in (columns or df.columns) if c in df.columns]
    st.dataframe(df[cols], use_container_width=True, height=height)
