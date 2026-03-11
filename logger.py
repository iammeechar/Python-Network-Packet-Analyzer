import json
import sys
from typing import Dict, Any, Optional


class EventLogger:
    """
    EventLogger handles output of detection events.

    Events can be printed to stdout or written to a file
    in JSON format.
    """

    def __init__(self, output_file: Optional[str] = None, pretty: bool = False):
        """
        Initialize the logger.

        Args:
            output_file: Optional path to log file
            pretty: Whether to pretty-print JSON
        """
        self.pretty = pretty
        self.file_handle = None

        if output_file:
            self.file_handle = open(output_file, "a")

    def log_event(self, event: Dict[str, Any]) -> None:
        """
        Log a detection event.

        Args:
            event: Dictionary containing event data
        """

        if self.pretty:
            json_event = json.dumps(event, indent=4)
        else:
            json_event = json.dumps(event)

        # Print to console
        print(json_event)
        sys.stdout.flush()

        # Write to file if enabled
        if self.file_handle:
            self.file_handle.write(json_event + "\n")
            self.file_handle.flush()

    def close(self) -> None:
        """
        Close the log file if it exists.
        """
        if self.file_handle:
            self.file_handle.close()