# Future work

* Full MaxMind / ipinfo GeoIP integration.
* Native EVTX writer so evaluation samples can ship as real `.evtx`.
* Deeper SAM `F`/`V` value decoding across every Windows version.
* Optional PyTorch Geometric training loop (the GCN math already runs
  on NumPy; `GCNConv` is used when PyG is installed).
* Sigma-rule export of every detection.
* Multi-host case merge.
