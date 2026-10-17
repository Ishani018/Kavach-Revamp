"""
kavach/agents.py
================

The agent tree: which agent made a call, and which security domain it belongs to.

A *domain* is one tree of cooperating agents that share risk state. Ministers
key their per-session state (CHANNEL taint and provenance, NAVIGATOR's
contract and event ledger) by domain, so a secret read by a sub-agent taints
the parent, and a parent's sensitive read is visible when its child tries to
send data out.

Two ways agents join a tree:

* Same host session. Hook payloads carry the host `session_id`, plus
  `agent_id` when the hook fires inside a sub-agent. Sub-agents share their
  parent's session_id, so they are already in the parent's domain; agent_id
  only adds attribution.
* Separate sessions. An orchestrator that runs each agent in its own session
  links the child session to its parent at SessionStart
  (`parent_session_id`). The child then resolves to the parent's domain.

Linking can only merge state (stricter), never split it. A link that would
create a cycle or exceed MAX_DEPTH is refused. State is in memory, like the
ministers' own state.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

MAX_DEPTH = 16


class AgentLinkError(ValueError):
    """A requested parent link is invalid (cycle, depth, or self-link)."""


@dataclass
class AgentNode:
    key: str                     # "session" or "session::agent"
    session_id: str
    agent_id: Optional[str]
    agent_type: Optional[str]
    parent: Optional[str]        # parent node key, None for a domain root
    depth: int
    started_at: float = field(default_factory=time.time)
    stopped_at: Optional[float] = None


def node_key(session_id: str, agent_id: Optional[str] = None) -> str:
    return session_id if not agent_id else f"{session_id}::{agent_id}"


class AgentRegistry:
    def __init__(self, max_depth: int = MAX_DEPTH) -> None:
        self.max_depth = max_depth
        self._nodes: Dict[str, AgentNode] = {}
        self._session_parent: Dict[str, str] = {}   # child session -> parent node key
        self._mutex = threading.RLock()
        self._domain_locks: Dict[str, threading.RLock] = {}

    # ---- registration -----------------------------------------------------

    def resolve(self, session_id: str, agent_id: Optional[str] = None,
                agent_type: Optional[str] = None) -> AgentNode:
        """The node for this (session, agent), created on first sight. A
        sub-agent's parent is its session's root node."""
        with self._mutex:
            root = self._nodes.get(session_id)
            if root is None:
                root = self._add(session_id, session_id, None, None, self._session_parent.get(session_id))
            if not agent_id:
                return root
            key = node_key(session_id, agent_id)
            node = self._nodes.get(key)
            if node is None:
                node = self._add(key, session_id, agent_id, agent_type, root.key)
            elif agent_type and not node.agent_type:
                node.agent_type = agent_type
            return node

    def link_session(self, session_id: str, parent_session_id: str,
                     parent_agent_id: Optional[str] = None) -> AgentNode:
        """Make `session_id` a child of another session (or of an agent in it)."""
        with self._mutex:
            parent = self.resolve(parent_session_id, parent_agent_id)
            if session_id == parent.session_id:
                raise AgentLinkError("a session cannot be its own parent")
            if session_id in [n.session_id for n in self._chain(parent)]:
                raise AgentLinkError("link would create a cycle")
            if parent.depth + 1 > self.max_depth:
                raise AgentLinkError(f"agent tree deeper than {self.max_depth}")
            existing = self._session_parent.get(session_id)
            if existing is not None and existing != parent.key:
                raise AgentLinkError("session is already linked to a different parent")
            root = self._nodes.get(session_id)
            if root is not None and parent.depth + 1 + self._height(root) > self.max_depth:
                raise AgentLinkError(f"agent tree deeper than {self.max_depth}")
            self._session_parent[session_id] = parent.key
            if root is None:
                return self.resolve(session_id)
            root.parent = parent.key
            self._redepth(root)
            return root

    def stop(self, session_id: str, agent_id: Optional[str] = None) -> AgentNode:
        node = self.resolve(session_id, agent_id)
        node.stopped_at = time.time()
        return node

    # ---- queries ----------------------------------------------------------

    def domain(self, node: AgentNode) -> str:
        """The session id of the tree's root: the key ministers store state under."""
        return self._chain(node)[-1].session_id

    def lineage(self, node: AgentNode) -> List[str]:
        """Node keys from this node up to the domain root."""
        return [n.key for n in self._chain(node)]

    def children(self, node: AgentNode) -> List[AgentNode]:
        with self._mutex:
            return [n for n in self._nodes.values() if n.parent == node.key]

    def domain_lock(self, domain: str) -> threading.RLock:
        """Serializes evaluation within one domain: taint and ledger order must
        follow the order calls were decided in, even when agents run in parallel."""
        with self._mutex:
            return self._domain_locks.setdefault(domain, threading.RLock())

    # ---- internals --------------------------------------------------------

    def _add(self, key, session_id, agent_id, agent_type, parent_key) -> AgentNode:
        parent = self._nodes.get(parent_key) if parent_key else None
        depth = parent.depth + 1 if parent else 0
        if depth > self.max_depth:
            raise AgentLinkError(f"agent tree deeper than {self.max_depth}")
        node = AgentNode(key=key, session_id=session_id, agent_id=agent_id, agent_type=agent_type,
                         parent=parent.key if parent else None, depth=depth)
        self._nodes[key] = node
        return node

    def _chain(self, node: AgentNode) -> List[AgentNode]:
        chain, seen = [node], {node.key}
        while chain[-1].parent is not None:
            parent = self._nodes.get(chain[-1].parent)
            if parent is None or parent.key in seen:
                break
            chain.append(parent)
            seen.add(parent.key)
        return chain

    def _height(self, node: AgentNode) -> int:
        return max((1 + self._height(c) for c in self.children(node)), default=0)

    def _redepth(self, node: AgentNode) -> None:
        parent = self._nodes.get(node.parent) if node.parent else None
        node.depth = parent.depth + 1 if parent else 0
        for child in self.children(node):
            self._redepth(child)
