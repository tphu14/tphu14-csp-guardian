# backend/tests/conftest.py
import sys
import os
from pathlib import Path

# Add backend/ directory to sys.path so pytest can find main, security, etc.
sys.path.insert(0, str(Path(__file__).parent.parent))

# Force test database before any imports
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.setdefault("GROQ_API_KEY", "test-key")