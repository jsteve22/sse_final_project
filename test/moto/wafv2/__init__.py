from ..core.models import base_decorator
from .models import wafv2_backends

wafv2_backend = wafv2_backends["us-east-1"]
mock_wafv2 = base_decorator(wafv2_backends)
