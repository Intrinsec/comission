#!/usr/bin/env python3

import json

class ComissionJSON:
    """ CoMisSion JSON Generator """

    def __init__(self, filename="output.json"):
        self.filename = filename
        self.data = {}

    def add_data(self, core_details, plugins, themes) -> None:
        self.data["core"] = core_details
        self.data["plugins"] = plugins
        self.data["themes"] = themes

    def generate_json(self) -> None:
        with open(self.filename, "w") as outfile:
            json.dump(self.data, outfile)
