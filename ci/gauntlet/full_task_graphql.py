"""A small GraphQL reader and fail-closed validator for the full-task gateway.

The gateway adds the operator's real GitHub token to a GraphQL request once policy allows it,
so policy must understand the whole document, not pattern-match pieces of it. This module
parses a document into operations, fields and fragments; any syntax it does not recognize is a
rejection. Only a short list of root fields is accepted for each operation kind, every
repository reference (literal or variable) must name a run-owned repository, and every nested
selection must appear in the SCHEMA allowlist (keyed on field name, never alias); all else is refused.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .full_task_graphql_schema import FRAGMENT_TYPES, MUTATION_PAYLOADS, SCHEMA

MAX_TOKENS = 20000
MAX_DEPTH = 16
# Match GraphQL's lexical grammar exactly: ASCII whitespace, comments that end at CR or LF, and block
# strings where only a backslash before three quotes is an escape. Anything else fails to tokenize.
TOKEN = re.compile(
    r"[ \t\r\n]+|,|#[^\n\r]*|(?P<spread>\.\.\.)|(?P<punct>[!$&():=@\[\]{|}])"
    r'|(?P<block>"""(?:\\"""|[^"\\]|\\(?!""")|"(?!""))*""")'
    r'|(?P<string>"(?:[^"\\\n\r]|\\.)*")|(?P<number>-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)'
    r"|(?P<name>[_A-Za-z][_0-9A-Za-z]*)"
)
QUERY_ROOTS = frozenset({"repository", "viewer"})
MUTATION_ROOTS = {
    "RepositoryCreate": frozenset({"createRepository"}),
    "PullRequestCreate": frozenset({"createPullRequest"}),
}
VIEWER_FIELDS = frozenset({"login", "id", "name", "url", "databaseId", "__typename"})
ID_KEYS = frozenset({"repositoryid", "headrepositoryid", "baserepositoryid", "repoid"})
CROSS_OWNER_KEYS = frozenset({"ownerid", "teamid", "templaterepositoryid", "organizationid"})


class GraphQLRejectedError(Exception):
    """The document is not one the gateway understands and may forward."""


@dataclass(frozen=True)
class Var:
    name: str


@dataclass
class Field:
    name: str
    args: dict[str, Any] = field(default_factory=dict)
    selections: list[Any] | None = None


@dataclass
class Spread:
    name: str


@dataclass
class Inline:
    type_name: str | None
    selections: list[Any]


def tokenize(text: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    position = 0
    while position < len(text):
        match = TOKEN.match(text, position)
        if match is None:
            raise GraphQLRejectedError("graphql-unparseable")
        position = match.end()
        if match.lastgroup:
            tokens.append((match.lastgroup, match.group()))
        if len(tokens) > MAX_TOKENS:
            raise GraphQLRejectedError("graphql-too-large")
    return tokens


class Parser:
    def __init__(self, tokens: list[tuple[str, str]]):
        self.tokens = tokens
        self.index = 0

    def peek(self) -> tuple[str, str]:
        return self.tokens[self.index] if self.index < len(self.tokens) else ("end", "")

    def take(self) -> tuple[str, str]:
        token = self.peek()
        self.index += 1
        return token

    def expect(self, text: str) -> None:
        if self.take()[1] != text:
            raise GraphQLRejectedError("graphql-unparseable")

    def name(self) -> str:
        kind, text = self.take()
        if kind != "name":
            raise GraphQLRejectedError("graphql-unparseable")
        return text

    def document(self) -> tuple[list[tuple[str, str, dict[str, Any], list[Any]]], dict[str, tuple[str, list[Any]]]]:
        operations: list[tuple[str, str, dict[str, Any], list[Any]]] = []
        fragments: dict[str, tuple[str, list[Any]]] = {}
        while self.peek()[0] != "end":
            kind, text = self.peek()
            if kind == "name" and text in ("query", "mutation", "subscription"):
                self.take()
                label = self.name()
                operations.append((text, label, *self.operation_rest()))
            elif kind == "name" and text == "fragment":
                self.take()
                label = self.name()
                if self.name() != "on":
                    raise GraphQLRejectedError("graphql-unparseable")
                type_name = self.name()
                self.no_directives()
                if label in fragments:
                    raise GraphQLRejectedError("graphql-duplicate-fragment")
                fragments[label] = (type_name, self.selection_set(0))
            else:
                raise GraphQLRejectedError("graphql-anonymous-or-unsupported")
        return operations, fragments

    def operation_rest(self) -> tuple[dict[str, Any], list[Any]]:
        """Parse variable definitions (their default values are checked like variables) and the selection set."""
        defaults: dict[str, Any] = {}
        if self.peek()[1] == "(":
            self.take()
            while self.peek()[1] != ")":
                self.expect("$")
                label = self.name()
                self.expect(":")
                self.variable_type()
                if self.peek()[1] == "=":
                    self.take()
                    defaults[label] = self.value(0)
                self.no_directives()
                if self.peek()[0] == "end":
                    raise GraphQLRejectedError("graphql-unparseable")
            self.take()
        self.no_directives()
        return defaults, self.selection_set(0)

    def variable_type(self) -> None:
        if self.peek()[1] == "[":
            self.take()
            self.variable_type()
            self.expect("]")
        else:
            self.name()
        if self.peek()[1] == "!":
            self.take()

    def no_directives(self) -> None:
        if self.peek()[1] == "@":
            raise GraphQLRejectedError("graphql-directive")

    def selection_set(self, depth: int) -> list[Any]:
        if depth > MAX_DEPTH:
            raise GraphQLRejectedError("graphql-too-deep")
        self.expect("{")
        items: list[Any] = []
        while self.peek()[1] != "}":
            if self.peek()[0] == "end":
                raise GraphQLRejectedError("graphql-unparseable")
            items.append(self.selection(depth))
        self.take()
        if not items:
            raise GraphQLRejectedError("graphql-unparseable")
        return items

    def selection(self, depth: int) -> Any:
        if self.peek()[0] == "spread":
            self.take()
            if self.peek()[1] == "on":
                self.take()
                type_name = self.name()
                self.no_directives()
                return Inline(type_name, self.selection_set(depth + 1))
            if self.peek()[1] == "{":
                return Inline(None, self.selection_set(depth + 1))
            label = self.name()
            self.no_directives()
            return Spread(label)
        label = self.name()
        if self.peek()[1] == ":":
            self.take()
            label = self.name()
        node = Field(label)
        if self.peek()[1] == "(":
            node.args = self.arguments()
        self.no_directives()
        if self.peek()[1] == "{":
            node.selections = self.selection_set(depth + 1)
        return node

    def arguments(self) -> dict[str, Any]:
        self.expect("(")
        found: dict[str, Any] = {}
        while self.peek()[1] != ")":
            key = self.name()
            self.expect(":")
            if key in found:
                raise GraphQLRejectedError("graphql-duplicate-argument")
            found[key] = self.value(0)
        self.take()
        return found

    def value(self, depth: int) -> Any:
        if depth > MAX_DEPTH:
            raise GraphQLRejectedError("graphql-too-deep")
        kind, text = self.take()
        if text == "$":
            return Var(self.name())
        if text == "[":
            items = []
            while self.peek()[1] != "]":
                if self.peek()[0] == "end":
                    raise GraphQLRejectedError("graphql-unparseable")
                items.append(self.value(depth + 1))
            self.take()
            return items
        if text == "{":
            fields: dict[str, Any] = {}
            while self.peek()[1] != "}":
                key = self.name()
                self.expect(":")
                fields[key] = self.value(depth + 1)
            self.take()
            return fields
        if kind == "block":
            return text[3:-3]
        if kind == "string":
            return _unquote(text)
        if kind == "number":
            return float(text) if re.search(r"[.eE]", text) else int(text)
        if kind == "name":
            return {"true": True, "false": False, "null": None}.get(text, text)
        raise GraphQLRejectedError("graphql-unparseable")


def _unquote(text: str) -> str:
    try:
        return str(json.loads(text))
    except ValueError as exc:
        raise GraphQLRejectedError("graphql-unparseable") from exc


def _resolve(value: Any, variables: dict[str, Any]) -> Any:
    if isinstance(value, Var):
        return variables.get(value.name)
    if isinstance(value, list):
        return [_resolve(item, variables) for item in value]
    if isinstance(value, dict):
        return {key: _resolve(item, variables) for key, item in value.items()}
    return value


@dataclass
class Checker:
    owns: Callable[[str, str], bool]
    owns_node: Callable[[str], bool]
    variables: dict[str, Any]
    fragments: dict[str, tuple[str, list[Any]]]
    references: int = 0

    def reference_walk(self, value: Any) -> None:
        """Every repository reference inside an argument or variable must be run-owned."""
        if isinstance(value, list):
            for item in value:
                self.reference_walk(item)
        elif isinstance(value, dict):
            lowered = {key.lower() for key in value}
            owner, name = value.get("owner"), value.get("name", value.get("repo"))
            if isinstance(owner, str) and isinstance(name, str) and "repositoryid" not in lowered:
                self.references += 1
                if not self.owns(owner, name):
                    raise GraphQLRejectedError("foreign-repository")
            for key, item in value.items():
                if key.lower() in ID_KEYS:
                    self.references += 1
                    if not isinstance(item, str) or not self.owns_node(item):
                        raise GraphQLRejectedError("foreign-repository-id")
                elif key.lower() in CROSS_OWNER_KEYS:
                    raise GraphQLRejectedError("cross-owner-reference")
                else:
                    self.reference_walk(item)

    @staticmethod
    def type_fits(condition: str, parent: str) -> bool:
        return condition == parent or condition in FRAGMENT_TYPES.get(parent, ())

    def expand(self, selections: list[Any], parent: str, seen: tuple[str, ...] = ()) -> list[Field]:
        """Flatten fragments; a type condition must be the parent type or one listed for it in FRAGMENT_TYPES."""
        fields: list[Field] = []
        for item in selections:
            if isinstance(item, Field):
                fields.append(item)
            elif isinstance(item, Inline):
                if item.type_name is not None and not self.type_fits(item.type_name, parent):
                    raise GraphQLRejectedError("graphql-fragment-type")
                fields.extend(self.expand(item.selections, parent, seen))
            else:
                if item.name in seen or item.name not in self.fragments:
                    raise GraphQLRejectedError("graphql-fragment")
                type_name, body = self.fragments[item.name]
                if not self.type_fits(type_name, parent):
                    raise GraphQLRejectedError("graphql-fragment-type")
                fields.extend(self.expand(body, parent, (*seen, item.name)))
        return fields

    def select(self, node: Field, parent: str) -> None:
        """Allow node only when SCHEMA lists its field name under the parent type; recurse into objects."""
        allowed = SCHEMA[parent]
        if node.name not in allowed:
            raise GraphQLRejectedError("graphql-selection-not-allowed")
        child_type = allowed[node.name]
        for value in node.args.values():
            self.reference_walk(_resolve(value, self.variables))
        if child_type is None:
            if node.selections is not None or node.args:
                raise GraphQLRejectedError("graphql-selection-not-allowed")
            return
        if node.selections is None:
            raise GraphQLRejectedError("graphql-selection-not-allowed")
        for child in self.expand(node.selections, child_type):
            self.select(child, child_type)

    def root(self, node: Field, roots: frozenset[str]) -> None:
        if node.name not in roots:
            raise GraphQLRejectedError("graphql-root-not-allowed")
        if node.name == "viewer":
            if node.args or node.selections is None:
                raise GraphQLRejectedError("graphql-viewer")
            children = self.expand(node.selections, "Viewer")
            if any(child.name not in VIEWER_FIELDS or child.selections or child.args for child in children):
                raise GraphQLRejectedError("graphql-viewer")
        elif node.name == "repository":
            if set(node.args) != {"owner", "name"} or node.selections is None:
                raise GraphQLRejectedError("graphql-repository-arguments")
            owner = _resolve(node.args["owner"], self.variables)
            name = _resolve(node.args["name"], self.variables)
            if not isinstance(owner, str) or not isinstance(name, str):
                raise GraphQLRejectedError("graphql-repository-arguments")
            self.references += 1
            if not self.owns(owner, name):
                raise GraphQLRejectedError("foreign-repository")
            for child in self.expand(node.selections, "Repository"):
                self.select(child, "Repository")
        else:
            if set(node.args) != {"input"} or not isinstance(node.args["input"], Var) or node.selections is None:
                raise GraphQLRejectedError("graphql-mutation-arguments")
            self.reference_walk(_resolve(node.args["input"], self.variables))
            payload = MUTATION_PAYLOADS[node.name]
            for child in self.expand(node.selections, payload):
                self.select(child, payload)


def validate(
    query: str,
    variables: dict[str, Any],
    *,
    owns: Callable[[str, str], bool],
    owns_node: Callable[[str], bool],
    queries: frozenset[str],
) -> tuple[str, str, int]:
    """Return (kind, operation name, repository references) or raise GraphQLRejectedError."""
    operations, fragments = Parser(tokenize(query)).document()
    if len(operations) != 1:
        raise GraphQLRejectedError("graphql-anonymous-or-multiple")
    kind, name, defaults, selections = operations[0]
    if kind == "subscription":
        raise GraphQLRejectedError("graphql-anonymous-or-multiple")
    if kind == "query" and name not in queries:
        raise GraphQLRejectedError("graphql-operation-not-allowed")
    if kind == "mutation" and name not in MUTATION_ROOTS:
        raise GraphQLRejectedError("graphql-operation-not-allowed")
    variables = {**{key: _resolve(item, {}) for key, item in defaults.items()}, **variables}
    checker = Checker(owns, owns_node, variables, fragments)
    checker.reference_walk(variables)
    roots = QUERY_ROOTS if kind == "query" else MUTATION_ROOTS[name]
    for node in checker.expand(selections, "Query" if kind == "query" else "Mutation"):
        checker.root(node, roots)
    return kind, name, checker.references
