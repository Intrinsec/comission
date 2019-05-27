"""
Details on the CMS core
"""


class Core:
    def __init__(self):
        self.version = ""
        self.last_version = None
        self.version_major = None
        self.alterations = []
        self.vulns = []
        self.notes = None
        self.ignored_files = []
