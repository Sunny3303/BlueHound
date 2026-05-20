import pytest
from unittest.mock import Mock, patch

from bluehound.detection.engine import DetectionEngine
from bluehound.core.detection_context import DetectionContext
from bluehound.core.types import (
    Finding,
    FindingCategory,
    Severity,
    Confidence,
    Evidence,
)


def create_mock_context():
    ctx = Mock(spec=DetectionContext)
    ctx.view = Mock()
    ctx.build.return_value = None
    return ctx


def test_engine_initialization():
    ctx = create_mock_context()
    engine = DetectionEngine(ctx)

    assert engine.context == ctx
    assert engine.factory is not None


def test_deduplicate_findings():
    ctx = create_mock_context()
    engine = DetectionEngine(ctx)

    f1 = Finding(
        id="TEST-1",
        category=FindingCategory.PRIVILEGE_EXPOSURE,
        severity=Severity.HIGH,
        confidence=Confidence.EXPLICIT,
        title="Test",
        description="Test",
        evidence=Evidence("x", {}, "r"),
        affected_principals=["S"],
    )

    unique = engine.deduplicate_findings([f1, f1])

    assert len(unique) == 1


def test_run_all_empty():
    ctx = create_mock_context()
    engine = DetectionEngine(ctx)

    with patch(
        "bluehound.detection.category_a.detect_privilege_exposure",
        return_value=[]
    ), patch(
        "bluehound.detection.category_b.detect_kerberos_abuse",
        return_value=[]
    ), patch(
        "bluehound.detection.category_c.detect_delegation_abuse",
        return_value=[]
    ):
        findings = engine.run_all_detections()

    assert findings == []


def test_statistics():
    ctx = create_mock_context()
    engine = DetectionEngine(ctx)

    finding = Finding(
        id="PRIV-1",
        category=FindingCategory.PRIVILEGE_EXPOSURE,
        severity=Severity.CRITICAL,
        confidence=Confidence.EXPLICIT,
        title="Test",
        description="Test",
        evidence=Evidence("x", {}, "r"),
        affected_principals=["S"],
    )

    engine._update_statistics([finding])

    stats = engine.get_statistics()

    assert stats["total_findings"] == 1
