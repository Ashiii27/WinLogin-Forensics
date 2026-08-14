# User guide

## Web UI

```bash
pip install -r requirements.txt
streamlit run src/app.py
```

1. Open **Home**.
2. Click **Load demo case** or upload EVTX / hive files.
3. Walk the **Events**, **Sessions**, **Anomalies**, **ATT&CK Matrix**,
   **Timeline**, and **Registry** pages.
4. Generate an HTML or PDF report from **Report**.
5. **Real-Time** replays a mock queue; on Windows the same engine can
   subscribe via `win32evtlog`.

## CLI

```bash
python src/cli/main.py parse --evtx-dir tests/fixtures/ --output-dir output/ --format pdf
python src/cli/main.py correlate --evtx-dir path/to/logs --output-dir output/
python src/cli/main.py detect --evtx-dir path/to/logs --output-dir output/ --threshold 0.5
python src/cli/main.py report --evtx-dir path/to/logs --output-dir output/ --format html
python src/cli/main.py live
```

## Evaluation & benchmark

```bash
python evaluation/run_evaluation.py --sample-dir evaluation/samples/
python benchmarking/run_all.py --sample-dir evaluation/samples/
```
