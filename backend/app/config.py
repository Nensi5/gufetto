"""Podešavanja aplikacije, čitaju se iz environment varijabli (.env)."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Gufetto"
    environment: str = "dev"

    # SQL Server u Docker-u; za lokalni rad bez Docker-a može sqlite:///./gufetto.db
    database_url: str = "sqlite:///./gufetto.db"

    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""

    # Koliko dugo važi keširan rezultat lookup-a (u satima)
    ioc_cache_ttl_hours: int = 24
    http_timeout_seconds: float = 10.0


@lru_cache
def get_settings() -> Settings:
    return Settings()
