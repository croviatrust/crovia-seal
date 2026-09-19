import sys
from pathlib import Path

# Make `app` and `protocol_profiles` importable whether pytest runs from the
# repository root or from integrations/seal-svc.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
