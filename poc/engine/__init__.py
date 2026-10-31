"""Generic decision-agent engine for the refusal-mishandling PoC.

Everything model-side is mocked: the independent variable is harness code,
not model behaviour.
"""
import logging

# Handlers log swallowed exceptions; keep that out of matrix output.
logging.getLogger(__name__).addHandler(logging.NullHandler())
