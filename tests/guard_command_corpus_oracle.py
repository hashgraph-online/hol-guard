"""Reviewed corpus oracle independent from Guard matcher output."""

from tests.guard_command_corpus_oracle_adversarial import ADVERSARIAL_ORACLE, PAIR_ORACLE
from tests.guard_command_corpus_oracle_benign import BENIGN_ORACLE
from tests.guard_command_corpus_oracle_loader import iter_adversarial_oracle, iter_benign_oracle, oracle_record
from tests.guard_command_corpus_oracle_types import (
    DecisionStatus,
    OracleFloor,
    OracleRecord,
    OracleSeed,
    PairOracleFacts,
)

__all__ = [
    "ADVERSARIAL_ORACLE",
    "BENIGN_ORACLE",
    "PAIR_ORACLE",
    "DecisionStatus",
    "OracleFloor",
    "OracleRecord",
    "OracleSeed",
    "PairOracleFacts",
    "iter_adversarial_oracle",
    "iter_benign_oracle",
    "oracle_record",
]
