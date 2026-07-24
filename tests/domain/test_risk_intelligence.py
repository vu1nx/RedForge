"""Tests for Risk Intelligence domain models."""

from dataclasses import FrozenInstanceError

import pytest  # type: ignore[reportMissingImports]

from redforge.domain.risk_intelligence import (
    RiskAssessment,
    RiskFactor,
    RiskFactorKind,
    RiskIntelligence,
    RiskLevel,
    risk_assessment_identifier,
    risk_level_for_score,
)


def _factor() -> RiskFactor:
    return RiskFactor(
        kind=RiskFactorKind.CVSS_BASE,
        contribution=50,
        explanation="Provider CVSS contributes priority",
        evidence=("cvss:7.1",),
    )


def _assessment(**overrides: object) -> RiskAssessment:
    values: dict[str, object] = {
        "asset_node_id": "graph:asset:a",
        "technology_node_id": "graph:technology:t",
        "vulnerability_node_id": "graph:vulnerability:v",
        "priority_score": 50,
        "confidence_score": 80,
        "data_completeness": 100,
    }
    values.update(overrides)
    return RiskAssessment(**values)  # type: ignore[arg-type]


def test_models_are_immutable_slotted_and_use_tuples() -> None:
    factor = _factor()
    assessment = _assessment(factors=(factor,), evidence=("path",))
    intelligence = RiskIntelligence(assessments=(assessment,))

    assert factor.evidence == ("cvss:7.1",)
    assert not hasattr(factor, "__dict__")
    assert not hasattr(assessment, "__dict__")
    assert not hasattr(intelligence, "__dict__")
    with pytest.raises(FrozenInstanceError):
        factor.contribution = 10  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        assessment.factors = ()  # type: ignore[misc]


def test_factor_requires_non_boolean_integer_contribution() -> None:
    with pytest.raises(TypeError):
        RiskFactor(
            kind=RiskFactorKind.DATA_QUALITY,
            contribution=True,  # type: ignore[arg-type]
            explanation="invalid",
        )


def test_assessment_identity_is_deterministic_from_graph_path_only() -> None:
    first = _assessment(priority_score=10, confidence_score=20)
    second = _assessment(priority_score=70, confidence_score=100)

    assert first.identifier == second.identifier
    assert first.identifier == risk_assessment_identifier(
        first.asset_node_id,
        first.technology_node_id,
        first.vulnerability_node_id,
    )
    assert _assessment(asset_node_id="graph:asset:other").identifier != first.identifier


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, RiskLevel.LOW),
        (19, RiskLevel.LOW),
        (20, RiskLevel.MEDIUM),
        (39, RiskLevel.MEDIUM),
        (40, RiskLevel.HIGH),
        (59, RiskLevel.HIGH),
        (60, RiskLevel.CRITICAL),
        (100, RiskLevel.CRITICAL),
    ],
)
def test_known_risk_level_mapping(score: int, expected: RiskLevel) -> None:
    assert risk_level_for_score(score) == expected
    assert _assessment(priority_score=score).level == expected


def test_unknown_is_independent_of_numeric_low_priority() -> None:
    assert risk_level_for_score(0, priority_known=False) == RiskLevel.UNKNOWN
    assert _assessment(priority_score=0, priority_known=False).level == RiskLevel.UNKNOWN
    assert _assessment(priority_score=0, priority_known=True).level == RiskLevel.LOW


@pytest.mark.parametrize("field", ["priority_score", "confidence_score", "data_completeness"])
@pytest.mark.parametrize("value", [-1, 101])
def test_bounded_integer_fields(field: str, value: int) -> None:
    with pytest.raises(ValueError):
        _assessment(**{field: value})


@pytest.mark.parametrize("field", ["priority_score", "confidence_score", "data_completeness"])
@pytest.mark.parametrize("value", [True, 50.0])
def test_bounded_fields_reject_booleans_and_non_integers(
    field: str, value: object
) -> None:
    with pytest.raises(TypeError):
        _assessment(**{field: value})
