import json
import os
from typing import Any, Dict

class ConfigLoader:
    """
    ConfigLoader loads detection engine configuration from a JSON file.

    The configuration includes:
    - Detection thresholds and time windows
    - Severity levels for each detection type
    - Output formatting options
    """

    def __init__(self, config_path: str = "config.json") -> None:
        """
        Initialize the loader with a path to the config file.

        Args:
            config_path: Path to the JSON configuration file. Defaults to 'config.json'.
        """
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self.load_config()

    def load_config(self) -> None:
        """
        Load and parse the JSON configuration.

        Raises:
            FileNotFoundError: If the config file does not exist.
            json.JSONDecodeError: If the JSON is invalid.
        """
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")

        with open(self.config_path, "r") as f:
            self.config = json.load(f)

        # Optional: validate required sections
        self._validate_config()

    def _validate_config(self) -> None:
        """
        Basic validation of configuration structure.
        Ensures detection and output sections exist.
        """
        if "detection" not in self.config:
            raise ValueError("Config missing 'detection' section")
        if "output" not in self.config:
            raise ValueError("Config missing 'output' section")

        # Check each detection type
        for detection_name, settings in self.config["detection"].items():
            if "enabled" not in settings:
                raise ValueError(f"Detection '{detection_name}' missing 'enabled' key")
            if "severity" not in settings or "numeric" not in settings["severity"] or "label" not in settings["severity"]:
                raise ValueError(f"Detection '{detection_name}' missing 'severity' definition")

    def get_detection_config(self, detection_type: str) -> Dict[str, Any]:
        """
        Return the configuration for a specific detection type.

        Args:
            detection_type: Name of the detection type (e.g., 'port_scan').

        Returns:
            Dict containing threshold, time_window, severity, etc.
        """
        return self.config["detection"].get(detection_type, {})

    def get_output_config(self) -> Dict[str, Any]:
        """
        Return the output configuration section.
        """
        return self.config.get("output", {})


# Example usage:
if __name__ == "__main__":
    loader = ConfigLoader()
    print("Port scan config:", loader.get_detection_config("port_scan"))
    print("Output config:", loader.get_output_config())