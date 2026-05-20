import pytest
from unittest.mock import Mock

from bluehound.core.detection_context import DetectionContext
from bluehound.core.graph_view import GraphView


def create_mock_view():
    view = Mock(spec=GraphView)

    view.get_tier0_assets.return_value = {
        "users": ["S-1-U"],
        "groups": ["S-1-G"],
        "computers": ["S-1-C"],
    }

    view.get_outgoing_edges.return_value = []

    return view


def test_context_initialization():
    view = create_mock_view()
    ctx = DetectionContext(view)

    assert ctx.view == view
    assert ctx._built is False


def test_context_build():
    view = create_mock_view()
    ctx = DetectionContext(view)

    ctx.build()

    assert ctx._built is True
    assert "S-1-U" in ctx._tier0_sids


def test_is_tier0():
    view = create_mock_view()
    ctx = DetectionContext(view)
    ctx.build()

    assert ctx.is_tier0("S-1-U") is True
    assert ctx.is_tier0("UNKNOWN") is False


def test_requires_build():
    view = create_mock_view()
    ctx = DetectionContext(view)

    with pytest.raises(RuntimeError):
        ctx.is_tier0("S-1-U")
