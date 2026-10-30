"""Migration hygiene checks that need no database (a full models-vs-migrations check is
`alembic check` against Postgres; see README)."""
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

BACKEND = Path(__file__).resolve().parents[1]


def _script_dir() -> ScriptDirectory:
    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "migrations"))
    return ScriptDirectory.from_config(cfg)


def test_single_migration_head():
    heads = _script_dir().get_heads()
    assert len(heads) == 1, f"Multiple migration heads {heads}: merge them (alembic merge)"


def test_migration_chain_is_linear_and_starts_at_initial_schema():
    revisions = list(_script_dir().walk_revisions())
    assert revisions, "no migrations found"
    assert revisions[-1].down_revision is None  # the oldest revision has no parent


def test_application_never_creates_tables_implicitly():
    """Tables are created only by Alembic; create_all in app code would bypass migrations."""
    offenders = [
        str(p.relative_to(BACKEND))
        for p in (BACKEND / "app").rglob("*.py")
        if "create_all" in p.read_text(encoding="utf-8")
    ]
    assert not offenders, f"create_all found in {offenders}; add an Alembic migration instead"
