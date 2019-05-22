"""
A CMS addon (could be a plugin, theme, module, etc.)
"""


class Addon:
    def __init__(self):
        self.name = None
        self.type = None
        self.subtype = None
        self.status = "todo"
        self.path = None
        self.filename = None
        self.version = None
        self.last_version = "Not found"
        self.last_release_date = None
        self.link = None
        self.notes = None
        self.url = None
        self.altered = None  # TODO replace with a boolean
        self.alterations = []
        self.cve = None  # TODO remove and check len(vulns) instead
        self.vulns = []
        self.ignored_files = []

    def get_report_list(self):
        return [
            self.status,
            self.name,
            self.version,
            self.last_version,
            self.last_release_date,
            self.link,
            self.subtype,
            self.altered,
            self.cve,
            self.notes,
        ]
