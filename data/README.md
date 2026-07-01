# Sample Data

This directory contains anonymized .evtx and Registry hive files for testing.

**No real user data is included in this repository.**

## Acquiring test artifacts from a live Windows system

1. Copy Security.evtx from C:\Windows\System32\winevt\Logs\ (requires admin rights)
2. Use a forensic acquisition tool (e.g. FTK Imager, Arsenal Image Mounter) to copy locked Registry hives:
   - C:\Windows\System32\config\SAM
   - C:\Windows\System32\config\SYSTEM
   - C:\Windows\System32\config\SECURITY
3. Place acquired files in data/samples/
"@

New-File "docs\methodology.md"  "# Methodology

> Document the forensic methodology, artifact sources, and analysis approach here."
New-File "docs\user_guide.md"   "# User Guide

> Step-by-step usage instructions with screenshots."
New-File "docs\event_ids.md"    "# Event ID Reference

> Field-level documentation for all covered Windows Security Event IDs."

New-File "output\reports\.gitkeep"  ""
New-File "output\exports\.gitkeep"  ""
New-File "data\samples\.gitkeep"    ""
New-File "docs\screenshots\.gitkeep" ""

# ─── Root-level Files ─────────────────────────────────────────────────────────

Write-Host "
[*] Creating root-level files..." -ForegroundColor Yellow

# requirements.txt
New-File "requirements.txt" @"
streamlit==1.37.0
python-evtx==0.7.4
xmltodict==0.13.0
regipy==3.1.0
python-registry==1.3.1
pandas==2.2.2
plotly==5.22.0
Jinja2==3.1.4
pdfkit==1.0.0
python-dateutil==2.9.0
colorama==0.4.6
