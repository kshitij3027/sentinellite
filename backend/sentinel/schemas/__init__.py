"""Source-schema registry. Maps a /ingest/{source} path value to its validator
+ normalizer. R1: each source validated against its native vendor schema."""

from __future__ import annotations

from typing import Any, Callable

from sentinel.schemas import aws_cloudtrail, falco, github, okta
from sentinel.schemas.common import NormalizedAlert, Source

# source value -> (payload, event_name) -> NormalizedAlert
PARSERS: dict[str, Callable[..., NormalizedAlert]] = {
    Source.github.value: github.to_normalized,
    Source.aws_cloudtrail.value: aws_cloudtrail.to_normalized,
    Source.okta_system_log.value: okta.to_normalized,
    Source.falco.value: falco.to_normalized,
}

SOURCES: tuple[str, ...] = tuple(PARSERS.keys())


def normalize(
    source: str, payload: dict[str, Any], event_name: str | None = None
) -> NormalizedAlert:
    """Validate `payload` against `source`'s schema and return a NormalizedAlert.

    Raises KeyError if `source` is unknown, pydantic.ValidationError if invalid."""
    parser = PARSERS[source]
    return parser(payload, event_name=event_name)


__all__ = ["PARSERS", "SOURCES", "normalize", "NormalizedAlert", "Source"]
