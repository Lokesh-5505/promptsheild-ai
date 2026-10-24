import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # MongoDB
    MONGO_URI: str = "mongodb://localhost:27017"
    MONGO_DB_NAME: str = "promptshield"
    
    # Authentication & Security
    DEFAULT_ADMIN_KEY: str = "ps_live_admin_secret_key_9921"
    RATE_LIMIT_PER_MINUTE: int = 60
    
    # NLP Models
    CLASSIFIER_MODEL: str = "distilbert-base-uncased"
    SIMILARITY_MODEL: str = "sentence-transformers/all-MiniLM-L6-v2"
    MAX_INPUT_LENGTH: int = 50000
    
    # Policy Threshold Defaults
    POLICY_LOW_MAX: int = 24
    POLICY_MEDIUM_MAX: int = 49
    POLICY_HIGH_MAX: int = 74
    STORE_RAW_TEXT: bool = False
    
    # Paths
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA_DIR: str = os.path.join(BASE_DIR, "data")
    ATTACK_SIGNATURES_PATH: str = os.path.join(DATA_DIR, "attack_signatures.json")
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
