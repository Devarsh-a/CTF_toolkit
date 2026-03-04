class Analyzer:
    def __init__(self, filepath):
        self.filepath = filepath
        self.findings = []

    def analyze(self):
        raise NotImplementedError("Analyzer must implement analyze()")