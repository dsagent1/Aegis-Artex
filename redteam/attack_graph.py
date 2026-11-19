"""
attack_graph.py -- IAM / Active-Directory / cloud attack-graph (BloodHound-lite) for RED-TEAM mode.

Models the mirror environment as a directed graph: nodes are principals/hosts/groups/creds, edges are
the relationships an attacker rides (has_session, member_of, admin_to, has_cred, can_rdp, can_privesc,
trusts, assume_role...). Finds privilege-escalation / lateral-movement PATHS from a starting foothold
to a high-value goal (e.g. Domain Admin / cloud-admin / a crown-jewel host), and the blast radius of
any node. This is the planning brain the post-exploitation leg drives -- all against the OWNED,
contained mirror twin, gated by redteam/authorization.py.

Pure + dependency-free; unit-testable without a live directory.
"""
from __future__ import annotations

import os
import json
from collections import defaultdict, deque

# edges that represent an attacker-usable step, with a rough "cost" (lower = easier/cheaper)
STEP_COSTS = {
    "has_session": 1, "has_cred": 1, "member_of": 1, "admin_to": 1, "can_rdp": 2,
    "can_psremote": 2, "can_privesc": 3, "assume_role": 2, "trusts": 2, "dcsync": 1,
}


class AttackGraph:
    def __init__(self):
        self.nodes = {}                       # id -> {type, props}
        self.edges = defaultdict(list)        # src -> [(dst, relation, cost)]

    def add_node(self, node_id, ntype="host", **props):
        self.nodes[node_id] = {"type": ntype, **props}
        return node_id

    def add_edge(self, src, dst, relation, cost=None):
        self.nodes.setdefault(src, {"type": "unknown"})
        self.nodes.setdefault(dst, {"type": "unknown"})
        self.edges[src].append((dst, relation, cost if cost is not None else STEP_COSTS.get(relation, 2)))

    def reachable(self, start):
        """Blast radius: every node reachable from `start` via attacker-usable edges."""
        seen, q = set(), deque([start])
        while q:
            n = q.popleft()
            for dst, _rel, _c in self.edges.get(n, []):
                if dst not in seen:
                    seen.add(dst); q.append(dst)
        return seen

    def paths(self, start, goal, max_len=8):
        """All simple attack paths start->goal (edge sequences), shortest-first-ish (BFS by hops)."""
        out, q = [], deque([(start, [start], [])])
        while q:
            node, npath, epath = q.popleft()
            if node == goal and epath:
                out.append({"nodes": npath, "edges": epath, "cost": sum(c for _, c in epath)})
                continue
            if len(npath) > max_len:
                continue
            for dst, rel, c in self.edges.get(node, []):
                if dst not in npath:                      # simple path (no cycles)
                    q.append((dst, npath + [dst], epath + [(rel, c)]))
        out.sort(key=lambda p: (len(p["nodes"]), p["cost"]))
        return out

    def best_path(self, start, goal, max_len=8):
        p = self.paths(start, goal, max_len)
        return p[0] if p else None

    def describe(self, path):
        if not path:
            return "no path"
        segs = []
        for i, (rel, c) in enumerate(path["edges"]):
            segs.append(f"{path['nodes'][i]} --{rel}--> {path['nodes'][i+1]}")
        return " ; ".join(segs) + f"  (hops={len(path['edges'])}, cost={path['cost']})"

    # ---- #5: PERSISTENCE -- the graph accumulates across runs so the planner searches an ever-richer
    # map instead of starting blind each run. Plain JSON (no deps); edges are deduped on merge/load. ----
    def to_dict(self) -> dict:
        return {"nodes": self.nodes,
                "edges": {s: [list(e) for e in es] for s, es in self.edges.items() if es}}

    def save(self, path: str = None) -> str:
        path = path or default_graph_path()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, sort_keys=True)
        os.replace(tmp, path)                      # atomic -- never leaves a half-written graph
        return path

    def _add_edge_unique(self, src, dst, relation, cost):
        for d, r, _c in self.edges.get(src, []):
            if d == dst and r == relation:
                return                             # dedup: same (dst, relation) already present
        self.edges[src].append((dst, relation, cost if cost is not None else STEP_COSTS.get(relation, 2)))

    def merge(self, other: "AttackGraph") -> "AttackGraph":
        """Union another graph into this one (nodes + deduped edges). Returns self so runs can chain:
        g = AttackGraph.load(); g.merge(from_findings(verified)); g.save()."""
        for nid, props in other.nodes.items():
            self.nodes.setdefault(nid, {}).update(props)
        for src, es in other.edges.items():
            self.nodes.setdefault(src, {"type": "unknown"})
            for dst, rel, c in es:
                self.nodes.setdefault(dst, {"type": "unknown"})
                self._add_edge_unique(src, dst, rel, c)
        return self

    @classmethod
    def from_dict(cls, d: dict) -> "AttackGraph":
        g = cls()
        for nid, props in (d.get("nodes") or {}).items():
            p = dict(props or {}); g.nodes[nid] = {"type": p.pop("type", "unknown"), **p}
        for src, es in (d.get("edges") or {}).items():
            for e in es:
                dst, rel = e[0], e[1]
                c = e[2] if len(e) > 2 else None
                g._add_edge_unique(src, dst, rel, c)
        return g

    @classmethod
    def load(cls, path: str = None) -> "AttackGraph":
        """Load the persistent graph (empty graph if none exists yet -- never raises on a fresh box)."""
        path = path or default_graph_path()
        if not os.path.exists(path):
            return cls()
        try:
            with open(path, encoding="utf-8") as f:
                return cls.from_dict(json.load(f))
        except Exception:
            return cls()                           # a corrupt store never blocks a run


def default_graph_path() -> str:
    """Where the persistent attack graph lives. Override with AEGIS_ATTACK_GRAPH; data, so gitignored."""
    return os.environ.get("AEGIS_ATTACK_GRAPH") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "attack_graph.json")


def persist_from_findings(findings, path: str = None) -> "AttackGraph":
    """#5 one-call accumulation step: load the persistent graph, merge in this run's verified findings,
    save, and return it. Safe + additive -- a post-run hook can call this without touching the loop's
    control flow, and the planner then searches the ever-richer accumulated map next run."""
    g = AttackGraph.load(path)
    g.merge(from_findings(findings))
    g.save(path)
    return g


def from_findings(findings):
    """Seed a graph from verified findings' coverage_tags: surface:/role:/cred: entities become nodes,
    and a verified access/privesc finding becomes an edge (so MODE-1 anchor expansion + the graph share
    the same ground truth)."""
    g = AttackGraph()
    for f in findings:
        if f.get("status") not in (None, "verified"):
            continue
        tags = f.get("coverage_tags", [])
        roles = [t.split(":", 1)[1] for t in tags if t.startswith("role:")]
        surfs = [t.split(":", 1)[1] for t in tags if t.startswith("surface:")]
        cls = (f.get("claim_type") or "")
        for r in roles:
            g.add_node(r, "principal")
            for s in surfs:
                g.add_node(s, "surface")
                rel = "can_privesc" if "privesc" in cls else "admin_to" if "role_overreach" in cls else "has_session"
                g.add_edge(r, s, rel)
    return g
