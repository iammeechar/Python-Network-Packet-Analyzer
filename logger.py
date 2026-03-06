import json
import sys
from datetime import datetime
from typing import Dict, Optional

class EventLogger:
    """
    EventLogger writes detection events to a file or stdout.
    Supports JSON output, pretty-printing, and optional timestamped filenames.
    """

    def __init__(self, output_file: Optional[str] = None, pretty: bool = False):
        """
        Initialize the logger.

        Args:
            output_file: Path to log file. If None, logs to stdout.
            pretty: Whether to pretty-print JSON for readability.
        """
        self.pretty = pretty
        self.output_target = open(output_file, "a") if output_file else sys.stdout

    def log_event(self, event: Dict):
        """
        Write a single event as JSON to the output target.

        Args:
            event: Detection event dictionary
        """
        if self.pretty:
            json.dump(event, self.output_target, indent=4)
            self.output_target.write("\n")
        else:
            json.dump(event, self.output_target)
            self.output_target.write("\n")
        self.output_target.flush()  # Ensure immediate write

    def close(self):
        """
        Close the output file if applicable.
        """
        if self.output_target is not sys.stdout:
            self.output_target.close()


# Example usage
if __name__ == "__main__":
    logger = EventLogger(pretty=True)
    test_event = {
        "event_type": "port_scan",
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.100",
        "details": {"connection_count": 120, "ports_hit": [22, 23, 80]},
        "severity": {"numeric": 3, "label": "medium"},
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    logger.log_event(test_event)