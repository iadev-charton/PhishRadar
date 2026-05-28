from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: str = "local"
    database_url: str = "sqlite:///./phishwatch.db"
    redis_url: str = "redis://localhost:6379/0"
    urlscan_api_key: str | None = None
    safebrowsing_api_key: str | None = None
    webrisk_api_key: str | None = None
    phishtank_api_key: str | None = None
    whoisxml_api_key: str | None = None
    securitytrails_api_key: str | None = None
    active_verification_enabled: bool = True
    http_timeout_seconds: float = 5.0
    max_redirects: int = 3
    max_variants_per_seed: int = 5000
    user_agent: str = Field(default="PhishWatch/0.1 defensive-monitoring contact=security@example.invalid")
    task_always_eager: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
