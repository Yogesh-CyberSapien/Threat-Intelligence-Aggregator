"""
config.py — Load and validate API keys from .env or environment variables.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ALIENVAULT_API_KEY: str  = os.getenv("ALIENVAULT_API_KEY", "")

    # VirusTotal base URL (v3)
    VT_BASE_URL: str = "https://www.virustotal.com/api/v3"

    # AlienVault OTX base URL (v1)
    OTX_BASE_URL: str = "https://otx.alienvault.com/api/v1"

    # Default request timeout (seconds)
    REQUEST_TIMEOUT: int = 15

    @classmethod
    def validate(cls) -> None:
        missing = []
        if not cls.VIRUSTOTAL_API_KEY:
            missing.append("VIRUSTOTAL_API_KEY")
        if not cls.ALIENVAULT_API_KEY:
            missing.append("ALIENVAULT_API_KEY")
        if missing:
            raise EnvironmentError(
                f"Missing required environment variables: {', '.join(missing)}\n"
                "Copy .env.example to .env and fill in your API keys."
            )
