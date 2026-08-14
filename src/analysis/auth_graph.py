"""
WinLogin Forensics - Authentication graph + GNN
===============================================
Builds a bipartite user ↔ workstation graph (edges weighted by auth
frequency), embeds nodes with a 2-layer GCN, and flags edges whose
embedding distance exceeds mean + 2σ as lateral-movement candidates.

Uses ``torch_geometric.nn.GCNConv`` when PyTorch Geometric is installed;
otherwise a NumPy implementation of the same GCN update rule.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

try:
    import torch
    from torch_geometric.nn import GCNConv

    PYG_AVAILABLE = True
except Exception:  # pragma: no cover
    PYG_AVAILABLE = False
    torch = None  # type: ignore
    GCNConv = None  # type: ignore


class _TorchGCN(torch.nn.Module if PYG_AVAILABLE else object):  # type: ignore[misc]
    """Two-layer GCNConv stack (only constructed when PyG is present)."""

    def __init__(self, in_dim: int, hidden: int, out_dim: int):
        if not PYG_AVAILABLE:
            raise RuntimeError("PyTorch Geometric is not available")
        super().__init__()
        self.conv1 = GCNConv(in_dim, hidden)
        self.conv2 = GCNConv(hidden, out_dim)

    def forward(self, x, edge_index, edge_weight=None):
        x = torch.relu(self.conv1(x, edge_index, edge_weight=edge_weight))
        x = self.conv2(x, edge_index, edge_weight=edge_weight)
        return x


class AuthGraphAnalyzer:
    """
    Bipartite authentication-graph analyser.

    Parameters
    ----------
    sessions : pd.DataFrame
        Correlated sessions (needs Username, WorkstationName).
    embedding_dim : int
        Output embedding size.
    hidden_dim : int
        Hidden GCN width.
    seed : int
        RNG seed for the NumPy / torch initialisation.
    """

    def __init__(
        self,
        sessions: pd.DataFrame,
        embedding_dim: int = 8,
        hidden_dim: int = 16,
        seed: int = 42,
    ):
        self.sessions = sessions.copy() if sessions is not None else pd.DataFrame()
        self.embedding_dim = embedding_dim
        self.hidden_dim = hidden_dim
        self.seed = seed
        self.nodes: List[str] = []
        self.node_index: Dict[str, int] = {}
        self.edges: List[Tuple[int, int, float]] = []
        self.embeddings: Optional[np.ndarray] = None
        self.backend: str = "numpy"

    def build(self) -> "AuthGraphAnalyzer":
        """
        Construct the undirected bipartite graph.

        Returns
        -------
        AuthGraphAnalyzer
            ``self``.
        """
        users = set()
        stations = set()
        weights: Dict[Tuple[str, str], float] = {}
        if not self.sessions.empty:
            for _, row in self.sessions.iterrows():
                user = f"user:{row.get('Username', '-')}"
                ws = f"ws:{row.get('WorkstationName', '-')}"
                users.add(user)
                stations.add(ws)
                weights[(user, ws)] = weights.get((user, ws), 0.0) + 1.0

        self.nodes = sorted(users) + sorted(stations)
        self.node_index = {n: i for i, n in enumerate(self.nodes)}
        self.edges = []
        for (u, w), wt in weights.items():
            if u in self.node_index and w in self.node_index:
                i, j = self.node_index[u], self.node_index[w]
                self.edges.append((i, j, float(wt)))
        return self

    def embed(self) -> np.ndarray:
        """
        Run a 2-layer GCN and cache node embeddings.

        Returns
        -------
        np.ndarray
            Array of shape ``(n_nodes, embedding_dim)``.
        """
        if not self.nodes:
            self.build()
        n = len(self.nodes)
        if n == 0:
            self.embeddings = np.zeros((0, self.embedding_dim))
            return self.embeddings

        # Degree-aware initial features: [is_user, is_ws, log1p(degree)]
        degree = np.zeros(n, dtype=float)
        for i, j, wt in self.edges:
            degree[i] += wt
            degree[j] += wt
        X = np.zeros((n, 3), dtype=float)
        for name, idx in self.node_index.items():
            X[idx, 0] = 1.0 if name.startswith("user:") else 0.0
            X[idx, 1] = 1.0 if name.startswith("ws:") else 0.0
            X[idx, 2] = np.log1p(degree[idx])

        if PYG_AVAILABLE and self.edges:
            self.backend = "pytorch_geometric"
            self.embeddings = self._embed_pyg(X)
        else:
            self.backend = "numpy"
            self.embeddings = self._embed_numpy(X)
        return self.embeddings

    def flag_lateral_movement(self) -> List[Dict[str, Any]]:
        """
        Flag bipartite edges whose embedding L2 distance is above mean + 2σ.

        Returns
        -------
        List[dict]
            Lateral-movement candidates with endpoints and z-score.
        """
        if self.embeddings is None:
            self.embed()
        if self.embeddings is None or len(self.edges) == 0:
            return []
        distances = []
        for i, j, wt in self.edges:
            dist = float(np.linalg.norm(self.embeddings[i] - self.embeddings[j]))
            distances.append(dist)
        arr = np.asarray(distances, dtype=float)
        mean, std = float(arr.mean()), float(arr.std()) if len(arr) > 1 else 0.0
        threshold = mean + 2.0 * std if std > 0 else mean + 1e-9
        findings = []
        for (i, j, wt), dist in zip(self.edges, distances):
            if dist > threshold:
                findings.append(
                    {
                        "user": self.nodes[i] if self.nodes[i].startswith("user:") else self.nodes[j],
                        "workstation": self.nodes[j] if self.nodes[j].startswith("ws:") else self.nodes[i],
                        "weight": wt,
                        "embedding_distance": dist,
                        "z_score": (dist - mean) / std if std else 0.0,
                        "threshold": threshold,
                        "backend": self.backend,
                        "anomaly": "Lateral Movement (GNN)",
                        "mitre_id": "T1021",
                        "severity": "High",
                    }
                )
        return findings

    def to_edge_frame(self) -> pd.DataFrame:
        """Return the bipartite edge list as a DataFrame."""
        if not self.nodes:
            self.build()
        rows = []
        for i, j, wt in self.edges:
            rows.append({"src": self.nodes[i], "dst": self.nodes[j], "weight": wt})
        return pd.DataFrame(rows)

    # ------------------------------------------------------------------

    def _embed_pyg(self, X: np.ndarray) -> np.ndarray:
        torch.manual_seed(self.seed)
        src, dst, wts = [], [], []
        for i, j, wt in self.edges:
            src.extend([i, j])
            dst.extend([j, i])
            wts.extend([wt, wt])
        edge_index = torch.tensor([src, dst], dtype=torch.long)
        edge_weight = torch.tensor(wts, dtype=torch.float)
        x = torch.tensor(X, dtype=torch.float)
        model = _TorchGCN(X.shape[1], self.hidden_dim, self.embedding_dim)
        model.eval()
        with torch.no_grad():
            emb = model(x, edge_index, edge_weight=edge_weight)
        return emb.cpu().numpy()

    def _embed_numpy(self, X: np.ndarray) -> np.ndarray:
        """
        Two-layer GCN: ``H' = tanh(Â H W)`` with ``Â = D^{-1/2}(A+I)D^{-1/2}``.
        """
        rng = np.random.default_rng(self.seed)
        n, fin = X.shape
        A = np.eye(n, dtype=float)
        for i, j, wt in self.edges:
            A[i, j] += wt
            A[j, i] += wt
        deg = np.clip(A.sum(axis=1), 1e-9, None)
        d_inv = np.diag(1.0 / np.sqrt(deg))
        a_hat = d_inv @ A @ d_inv
        w1 = rng.normal(0, 0.5, size=(fin, self.hidden_dim))
        w2 = rng.normal(0, 0.5, size=(self.hidden_dim, self.embedding_dim))
        h = np.tanh(a_hat @ X @ w1)
        h = a_hat @ h @ w2
        # L2-normalise rows so distances are comparable
        norms = np.linalg.norm(h, axis=1, keepdims=True)
        norms = np.clip(norms, 1e-9, None)
        return h / norms


def analyze_auth_graph(sessions: pd.DataFrame, **kwargs: Any) -> Dict[str, Any]:
    """
    Build the auth graph, embed, and return lateral-movement candidates.

    Parameters
    ----------
    sessions : pd.DataFrame
        Session table.
    **kwargs
        Forwarded to :class:`AuthGraphAnalyzer`.

    Returns
    -------
    dict
        ``edges``, ``findings``, ``backend``, ``n_nodes``.
    """
    analyzer = AuthGraphAnalyzer(sessions, **kwargs)
    analyzer.build()
    analyzer.embed()
    return {
        "edges": analyzer.to_edge_frame(),
        "findings": analyzer.flag_lateral_movement(),
        "backend": analyzer.backend,
        "n_nodes": len(analyzer.nodes),
    }
