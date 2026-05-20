from bluehound.core.graph import GraphConnector
from bluehound.core.graph_view import GraphView
from bluehound.core.detection_context import DetectionContext
from bluehound.detection.engine import DetectionEngine

print("Pipeline loading...")

graph = GraphConnector("bolt://x", "u", "p")
graph.driver = object()  # mock connection

view = GraphView(graph)
view._loaded = True

ctx = DetectionContext(view)
ctx._built = True

engine = DetectionEngine(ctx)

print("Pipeline OK")
