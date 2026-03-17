# detectors/base_detector.py

class BaseDetector:
    def __init__(self, config):
        self.config = config

    def process(self, packet):
        """
        Must return a list of events
        """
        raise NotImplementedError
