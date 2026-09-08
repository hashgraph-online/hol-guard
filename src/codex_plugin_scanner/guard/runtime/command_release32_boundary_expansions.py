"""Release 3.2 expansions that remain owned by existing command Extension IDs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import final

from .command_extension_matchers import executable_names
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_rules import CommandSafetyRule

_DESTRUCTIVE_SQL_PREFIXES = (
    "alter database ",
    "alter schema ",
    "alter table ",
    "delete from ",
    "drop database ",
    "drop schema ",
    "drop table ",
    "drop view ",
    "truncate ",
    "update ",
)
_DESTRUCTIVE_MONGO_PREFIXES = (
    "db.dropdatabase(",
    "db.dropuser(",
    "db.getcollection(",
    "db.",
)


def _basename(value: str | None) -> str:
    if value is None:
        return ""
    return value.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _normalized_statement(value: str) -> str:
    return " ".join(value.strip().lower().split())


def _destructive_sql(value: str) -> bool:
    statement = _normalized_statement(value).lstrip(". ")
    return any(statement.startswith(prefix) for prefix in _DESTRUCTIVE_SQL_PREFIXES)


@final
@dataclass(frozen=True, slots=True)
class SqlOptionMatcher:
    """Match destructive SQL passed through a documented one-shot command option."""

    executables: frozenset[str]
    options: frozenset[str]

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if _basename(segment.executable) not in self.executables:
                continue
            arguments = segment.arguments
            for argument_index, argument in enumerate(arguments):
                lowered = argument.lower()
                value: str | None = None
                if lowered in self.options and argument_index + 1 < len(arguments):
                    value = arguments[argument_index + 1]
                else:
                    for option in self.options:
                        if lowered.startswith(f"{option}="):
                            value = argument.split("=", 1)[1]
                            break
                if value is not None and _destructive_sql(value):
                    evidence.append(
                        MatcherEvidence(
                            segment_index=index,
                            executable=segment.executable,
                            detail="Matched destructive SQL in a structured one-shot client option.",
                        )
                    )
                    break
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class SqliteStatementMatcher:
    """Match destructive SQL or destructive SQLite dot commands in positional statements."""

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if _basename(segment.executable) not in executable_names("sqlite3"):
                continue
            for argument in segment.arguments[1:]:
                statement = _normalized_statement(argument)
                if _destructive_sql(statement) or statement.startswith((".restore ", ".import ")):
                    evidence.append(
                        MatcherEvidence(
                            segment_index=index,
                            executable=segment.executable,
                            detail="Matched destructive SQLite statement in a structured positional argument.",
                        )
                    )
                    break
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class MongoEvalMatcher:
    """Match explicit destructive mongosh --eval programs without re-parsing shell text."""

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if _basename(segment.executable) not in executable_names("mongosh"):
                continue
            arguments = segment.arguments
            for argument_index, argument in enumerate(arguments):
                lowered = argument.lower()
                value: str | None = None
                if lowered in {"--eval", "-e"} and argument_index + 1 < len(arguments):
                    value = arguments[argument_index + 1]
                elif lowered.startswith("--eval="):
                    value = argument.split("=", 1)[1]
                if value is None:
                    continue
                program = "".join(value.lower().split())
                destructive = (
                    "dropdatabase(" in program
                    or ".drop(" in program
                    or ".deleteone(" in program
                    or ".deletemany(" in program
                    or ".remove(" in program
                )
                if destructive:
                    evidence.append(
                        MatcherEvidence(
                            segment_index=index,
                            executable=segment.executable,
                            detail="Matched destructive MongoDB operation in a structured --eval argument.",
                        )
                    )
                    break
        return tuple(evidence)


def _rule(
    extension_id: str,
    title: str,
    matcher,
    action_class: str,
    safer_alternative: str,
    *,
    network: bool = True,
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=f"{extension_id}.direct-client-mutation",
        title=title,
        description=f"Identifies destructive one-shot mutations through {title.lower()}.",
        severity="critical",
        risk_classes=(("destructive_shell", "network_egress") if network else ("destructive_shell",)),
        action_classes=(action_class,),
        safer_alternatives=(safer_alternative,),
        matcher=matcher,
    )


RELEASE32_DATABASE_EXPANSION_RULES = (
    _rule(
        "command.database.postgresql",
        "PostgreSQL psql",
        SqlOptionMatcher(executables=executable_names("psql"), options=frozenset({"-c", "--command"})),
        "PostgreSQL destructive command",
        "Inspect the selected database and run the statement inside a disposable transaction or backup-restored copy first.",
    ),
    _rule(
        "command.database.mysql",
        "MySQL client",
        SqlOptionMatcher(executables=executable_names("mysql"), options=frozenset({"-e", "--execute"})),
        "MySQL destructive command",
        "Inspect the selected schema and verify a current backup before destructive SQL.",
    ),
    _rule(
        "command.database.mongodb",
        "MongoDB mongosh",
        MongoEvalMatcher(),
        "MongoDB destructive command",
        "Inspect the selected database and collection set before destructive mongosh evaluation.",
    ),
    _rule(
        "command.database.sqlite",
        "SQLite client",
        SqliteStatementMatcher(),
        "SQLite destructive command",
        "Copy the database file and test destructive statements against the copy first.",
        network=False,
    ),
)
