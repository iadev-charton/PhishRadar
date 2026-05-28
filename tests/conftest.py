import os
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("TASK_ALWAYS_EAGER", "true")
os.environ.setdefault("ACTIVE_VERIFICATION_ENABLED", "false")
