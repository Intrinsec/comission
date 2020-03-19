#!/usr/bin/env python3

from comission.CMS.models.Vulnerability import Vulnerability
from comission.CMS.models.Core import Core
from comission.CMS.models.Alteration import Alteration
from comission.CMS.models.Addon import Addon

"""
A dataset to test various stage of a CMS analysis
"""

class DataSet:
    def __init__(self):

        # Dataset specific to WordPress
        self.addon_wp_stage0 = Addon()
        self.addon_wp_stage0.type = "plugins"
        self.addon_wp_stage0.name = "w3-total-cache"
        self.addon_wp_stage0.filename = ""
        self.addon_wp_stage0.version = ""
        self.addon_wp_stage0.notes = ""
        self.addon_wp_stage0.subtype = "mu"

        self.addon_wp_stage1 = Addon()
        self.addon_wp_stage1.type = "plugins"
        self.addon_wp_stage1.name = "w3-total-cache"
        self.addon_wp_stage1.filename = "w3-total-cache.php"
        self.addon_wp_stage1.version = ""
        self.addon_wp_stage1.notes = ""
        self.addon_wp_stage1.subtype = ""

        self.addon_wp_stage2 = Addon()
        self.addon_wp_stage2.type = "plugins"
        self.addon_wp_stage2.name = "w3-total-cache"
        self.addon_wp_stage2.last_version = ""
        self.addon_wp_stage2.last_release_date = ""
        self.addon_wp_stage2.link = ""
        self.addon_wp_stage2.version = "0.9.4.1"
        self.addon_wp_stage2.subtype = ""
        self.addon_wp_stage2.vulns = []
        self.addon_wp_stage2.alterations = []

        # Dataset specific to Drupal analysis

        self.addon_dpl_stage1 = Addon()
        self.addon_dpl_stage1.type = "plugins"
        self.addon_dpl_stage1.name = "xmlsitemap"
        self.addon_dpl_stage1.filename = "xmlsitemap.info"
        self.addon_dpl_stage1.version = ""
        self.addon_dpl_stage1.notes = ""

        self.addon_dpl_stage2 = Addon()
        self.addon_dpl_stage2.type = "plugins"
        self.addon_dpl_stage2.name = "media_youtube"
        self.addon_dpl_stage2.last_version = ""
        self.addon_dpl_stage2.last_release_date = ""
        self.addon_dpl_stage2.link = ""
        self.addon_dpl_stage2.version = "7.x-3.4"
        self.addon_dpl_stage2.notes = ""
        self.addon_dpl_stage2.alterations = []

        self.alteration = Alteration()
        self.alteration.type = ""
        self.alteration.target = ""
        self.alteration.file = ""
        self.alteration.type = ""

        self.vuln = Vulnerability()
        self.vuln.name = "Vuln name"
        self.vuln.link = ""
        self.vuln.type = ""
        self.vuln.poc = ""
        self.vuln.fixed_in = ""

        self.core = Core()
        self.core.version = "4.5.1"
        self.core.last_version = "4.8"
        self.core.version_major = "4"
        self.core.alterations = [self.alteration, self.alteration, self.alteration]
        self.core.vulns = [self.vuln, self.vuln, self.vuln]

        self.plugin = Addon()
        self.plugin.type = "plugins"
        self.plugin.name = "Name plugin"
        self.plugin.version = "1.0"
        self.plugin.last_version = "2.0"
        self.plugin.last_release_date = "2017-08-25"
        self.plugin.link = "https://test.link.addon"
        self.plugin.altered = "YES"
        self.plugin.subtype = ""
        self.plugin.cve = "YES"
        self.plugin.vulns = [self.vuln, self.vuln, self.vuln]
        self.plugin.notes = ""
        self.plugin.alterations = [self.alteration, self.alteration, self.alteration]
        self.plugin.filename = ""

        self.muplugin = Addon()
        self.muplugin.type = "plugins"
        self.muplugin.name = "Name plugin"
        self.muplugin.version = "1.0"
        self.muplugin.last_version = "2.0"
        self.muplugin.last_release_date = "2017-08-25"
        self.muplugin.link = "https://test.link.addon"
        self.muplugin.altered = "YES"
        self.muplugin.subtype = "mu"
        self.muplugin.cve = "YES"
        self.muplugin.vulns = [self.vuln, self.vuln, self.vuln]
        self.muplugin.notes = ""
        self.muplugin.alterations = [self.alteration, self.alteration, self.alteration]
        self.muplugin.filename = ""

        self.theme = Addon()
        self.theme.type = "themes"
        self.theme.name = "Name theme"
        self.theme.version = "1.0"
        self.theme.last_version = "2.0"
        self.theme.last_release_date = "2017-08-25"
        self.theme.link = "https://test.link.addon"
        self.theme.altered = "YES"
        self.theme.subtype = ""
        self.theme.cve = "YES"
        self.theme.vulns = [self.vuln, self.vuln, self.vuln]
        self.theme.notes = ""
        self.theme.alterations = [self.alteration, self.alteration, self.alteration]
        self.theme.filename = ""

        self.plugins = [self.plugin, self.plugin, self.muplugin]
        self.themes = [self.theme for _ in range(3)]

