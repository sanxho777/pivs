from dataclasses import dataclass, field
from typing import List


@dataclass
class Finding:
    category: str
    key: str
    value: str
    source: str


@dataclass
class ResultSet:
    pivot: str
    pivot_type: str
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def add(self, category: str, key: str, value: str, source: str) -> None:
        self.findings.append(Finding(category, key, str(value), source))

    def add_error(self, error: str) -> None:
        self.errors.append(error)


class BaseModule:
    """Abstract base — every intelligence module inherits this."""

    @property
    def name(self) -> str:
        raise NotImplementedError

    def run(self, pivot: str, results: ResultSet) -> None:
        raise NotImplementedError

    def enrich(self, pivot: str, results: ResultSet) -> None:
        """
        Optional second-pass enrichment using data gathered in run().
        Default is no-op — override in subclasses to add deeper intel.
        """
        pass
