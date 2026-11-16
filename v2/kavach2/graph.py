"""Provenance graph for systems of several agents.

When agents message each other, the origin of information is lost: an agent that receives "pay account X"
from a colleague cannot tell whether X came from the user or from a web page the colleague read. This graph
records what every agent was told, read and sent, and traces each argument of a proposed action back across
the messages to where the value first entered the system.

Model-free. It knows nothing about attacks; it only follows values.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .provenance import _leaves, contains, traceable
from .speaker import Decision
from .types import Action, Opinion, Origin, Verdict


@dataclass(frozen=True)
class Node:
    id: int
    kind: str                 # "user" | "read" | "message"
    agent: str                # the agent whose context this entered
    text: str
    source: str               # "user", the tool name, or the sending agent
    sent_after: Optional[int] = None  # for messages: the sender had seen nodes with id < sent_after


@dataclass(frozen=True)
class Trace:
    origin: Origin
    path: tuple[int, ...] = ()   # node ids, from the acting agent back to where the value entered
    composed_by: Optional[str] = None


@dataclass
class ProvenanceGraph:
    nodes: list[Node] = field(default_factory=list)

    def _add(self, kind: str, agent: str, text: str, source: str, sent_after: Optional[int] = None) -> Node:
        node = Node(len(self.nodes), kind, agent, text, source, sent_after)
        self.nodes.append(node)
        return node

    def user_says(self, agent: str, text: str) -> Node:
        """The human user gives `agent` a request. The only trusted entry point."""
        return self._add("user", agent, text, "user")

    def reads(self, agent: str, tool: str, output: str) -> Node:
        """`agent` receives a tool's output. Untrusted."""
        return self._add("read", agent, output, tool)

    def sends(self, sender: str, receiver: str, text: str) -> Node:
        """`sender` messages `receiver`. Neither trusted nor untrusted: it depends on what it carries."""
        return self._add("message", receiver, text, sender, sent_after=len(self.nodes))

    def trace(self, agent: str, value: Any, before: Optional[int] = None) -> Trace:
        """Where did `value`, as known to `agent`, first enter the system?

        A path that reaches the user's request wins; otherwise a path that reaches a tool output; otherwise
        the value was composed by the agent furthest back that passed it on.
        """
        if not traceable(value):
            return Trace(Origin.UNTRACED)
        limit = len(self.nodes) if before is None else before
        seen = [n for n in self.nodes[:limit] if n.agent == agent and contains(value, n.text)]
        for node in seen:
            if node.kind == "user":
                return Trace(Origin.USER, (node.id,))
        best: Optional[Trace] = None
        for node in seen:
            if node.kind == "read":
                found = Trace(Origin.READ, (node.id,))
            else:  # a message: ask where its sender got the value, as of when it was sent
                up = self.trace(node.source, value, before=node.sent_after)
                found = Trace(up.origin, (node.id, *up.path), up.composed_by or node.source)
            if found.origin is Origin.USER:
                return found
            if best is None or (found.origin is Origin.READ and best.origin is not Origin.READ):
                best = found
        return best or Trace(Origin.NEW, (), agent)

    def traces(self, agent: str, action: Action) -> dict[str, Trace]:
        return {path: self.trace(agent, value) for path, value in _leaves(action.args, "")}

    def review(self, agent: str, action: Action, mode: str = "strict") -> Decision:
        """Same two rules as the single-agent reviewer, applied to origins traced across agents."""
        if action.changes_state is False:
            return Decision(Verdict.ALLOW, "tool declares the action read-only", ())
        traced = self.traces(agent, action)
        from_read = sorted(p for p, t in traced.items() if t.origin is Origin.READ)
        from_user = sorted(p for p, t in traced.items() if t.origin is Origin.USER)
        if not from_read:
            verdict, reason = Verdict.ALLOW, "no argument traces back only to tool output"
        elif mode == "anchored" and from_user:
            verdict, reason = Verdict.ALLOW, "the user named " + ", ".join(from_user)
        else:
            verdict, reason = Verdict.ASK, "traces back to tool output, not to the user: " + ", ".join(from_read)
        return Decision(verdict, reason, (Opinion("provenance-graph", verdict, reason),))
