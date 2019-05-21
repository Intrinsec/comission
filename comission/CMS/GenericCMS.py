#!/usr/bin/env python3


class GenericCMS:
    """ Generic CMS object """

    site_url = ""
    download_core_url = ""
    download_addon_url = ""
    cve_ref_url = ""

    def __init__(self):

        self.core_details = {"infos": [], "alterations": [], "vulns": []}
        self.plugins = []

    def get_core_version(self, cms_path):
        """
        Get the CMS core version
        """
        raise NotImplemented

    def get_addon_version(self, addon, addon_path, version_file_regexp):
        """
        Get a plugin version
        """
        raise NotImplemented

    def get_core_last_version(self, url):
        """
        Get the last released of the CMS
        """
        raise NotImplemented

    def get_addon_last_version(self, addon):
        """
        Get the last released of the plugin and the date
        """
        raise NotImplemented

    def check_core_alteration(self, core_url):
        """
        Check if the core have been altered
        """
        raise NotImplemented

    def check_addon_alteration(self, addon, addon_path, temp_directory):
        """
        Check if the plugin have been altered
        """
        raise NotImplemented

    def check_vulns_core(self, version_core):
        """
        Check if there are any vulns on the CMS core used
        """
        raise NotImplemented

    def check_vulns_addon(self, addon):
        """
        Check if there are any vulns on the plugin
        """
        raise NotImplemented

    def core_analysis(self):
        """
        CMS Core analysis, return a dict {"infos": [], "alterations": [], "vulns":[]}
        """
        raise NotImplemented

    def addon_analysis(self, addon_type):
        """
        CMS plugin analysis, return a list of dict
        """
        raise NotImplemented
