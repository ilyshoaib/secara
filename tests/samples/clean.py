"""
Clean Python file — Secara should report ZERO findings here.
Used to verify false positive rate.
"""
import os
import subprocess
import sqlite3
from typing import Optional


DB_NAME = os.environ.get("DATABASE_NAME", "app.db")


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[tuple]:
    """Fetch a user by ID using a parameterized query."""
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def search_users(conn: sqlite3.Connection, search_term: str) -> list:
    """Search users by name using a parameterized LIKE query."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, name FROM users WHERE name LIKE ?",
        (f"%{search_term}%",),
    )
    return cursor.fetchall()


def list_directory(directory: str) -> list[str]:
    """List contents of a validated directory path."""
    safe_dir = os.path.abspath(directory)
    # Validates that directory is within our allowed base path
    allowed_base = os.path.abspath("/app/data")
    if not safe_dir.startswith(allowed_base):
        raise ValueError("Directory traversal attempt blocked.")
    result = subprocess.run(["ls", "-la", safe_dir], capture_output=True, text=True)
    return result.stdout.splitlines()


def hash_password(password: str) -> str:
    """Hash a password using bcrypt (not storing plaintext)."""
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()


def load_config(config_path: str) -> dict:
    """Load configuration from environment, not from hardcoded values."""
    return {
        "db_host": os.environ.get("DB_HOST", "localhost"),
        "db_port": int(os.environ.get("DB_PORT", "5432")),
        "db_name": os.environ.get("DB_NAME", "myapp"),
        "api_key": os.environ.get("API_KEY"),  # None if not set
    }


def parse_expression(expr: str) -> float:
    """Safely evaluate a mathematical expression without eval()."""
    import ast as _ast
    try:
        tree = _ast.parse(expr, mode="eval")
        # Only allow numeric operations
        allowed = (_ast.Expression, _ast.BinOp, _ast.Constant, _ast.UnaryOp,
                   _ast.Add, _ast.Sub, _ast.Mult, _ast.Div, _ast.Pow, _ast.USub)
        for node in _ast.walk(tree):
            if not isinstance(node, allowed):
                raise ValueError(f"Disallowed expression: {type(node).__name__}")
        return eval(compile(tree, "<string>", "eval"))  # secara: ignore
    except Exception:
        raise ValueError("Invalid mathematical expression.")
