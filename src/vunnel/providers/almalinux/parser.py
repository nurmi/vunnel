from __future__ import annotations

import json
import os

import requests

from vunnel import utils
from vunnel.utils.vulnerability import Vulnerability

# TODO: investigate the 'module' mappings, seeing some partial/odd
# elements in the data and need to verify the final implications (in
# particular when reporting fixed versions across modules)

# TODO: re-visit possible error paths / bailouts in the parser to
# guarantee progress and proper instructive/useful warnings

# TODO: re-visit record gets defaulting to either "" or None, align
# with expectations of the resulting OS schema

NAMESPACE = "almalinux"
ALMALINUX_URL_BASE = "https://errata.almalinux.org/{}/errata.json"


class Parser:
    def __init__(self, workspace, download_timeout, allow_versions, logger):
        self.workspace = workspace
        self.download_timeout = download_timeout
        self.allow_versions = allow_versions
        self.urls: list[str] = []
        self.logger = logger

    def _download(self) -> list[str]:
        # TODO - check for last version + 1, based on config?
        return [self._download_version(v) for v in self.allow_versions]

    def _download_version(self, version: str) -> str:
        localfilename = f"almalinux_{version}.json"
        namespace = f"almalinux:{version}"
        url = ALMALINUX_URL_BASE.format(version)
        r = requests.get(url, timeout=self.download_timeout)
        destination = os.path.join(self.workspace.input_path, localfilename)
        with open(destination, "wb") as writer:
            writer.write(r.content)
        return destination, namespace

    def get(self):
        for local_file_path, namespace in self._download():
            with open(local_file_path) as FH:
                alma_records = json.loads(FH.read())

            # TODO: consider adding an alma record schema check, here

            for alma_record in alma_records:
                try:
                    vidmap = self.parse_alma_record(alma_record, namespace)
                    for vid in vidmap:
                        yield namespace, vid, vidmap[vid].to_payload()
                except Exception as err:
                    self.logger.warning(f"skipping alma record - exception: {err}")

    def _parse_severity(self, in_severity):
        severity_dict = {
            "none": "Unknown",
            "low": "Low",
            "moderate": "Medium",
            "important": "High",
            "critical": "Critical",
        }
        return severity_dict[in_severity.lower()]

    def _parse_linkrefs(self, in_refs, vid, namespace):
        cves = []
        link = None
        for ref in in_refs:
            reftype = ref.get("type", "")
            reflink = ref.get("href", None)
            refid = ref.get("id", None)

            if reftype == "self":
                link = reflink
            elif reftype == "cve" and refid:
                cves.append(refid)

        if link is None:
            # handle case where the self link isn't set (seen in some records) - construct a
            #
            # https://errata.almalinux.org/8/ALSA-2021-4154.html
            #
            # url from an ALSA-2021:4154 vid
            #
            try:
                nsname, nsvers = namespace.split(":", 1)

                html = f"{vid}.html"
                pre, post = vid.split(":", 1)
                if pre and post:
                    html = f"{pre}-{post}.html"
                link = f"https://errata.almalinux.org/{nsvers}/{html}"
            except Exception as err:
                self.logger.warning(f"self link not set for vulnerability {vid}, leaving link null.  exception: {err}")

        return (link, cves)

    def _parse_moduleinfo(self, in_module_name, in_module_version):
        module_info = None
        if in_module_name:
            module_info = in_module_name
            if in_module_version:
                module_info += f":{in_module_version}"

        return module_info

    def _parse_vendor_advisory(self, vid, link):
        wont_fix = False
        vendor_advisory = {"NoAdvisory": False, "AdvisorySummary": []}
        if wont_fix:
            vendor_advisory = {"NoAdvisory": True}
        elif vid and link:
            vendor_advisory["AdvisorySummary"].append(
                {
                    "ID": vid,
                    "Link": link,
                },
            )

        return vendor_advisory

    def _parse_fixed_ins(self, in_pkgs, namespace, module_info, vendor_advisory):
        fins = {}
        for pkg in in_pkgs:
            if pkg["arch"] not in ["x86_64", "noarch"]:
                continue

            version = "{}:{}-{}".format(pkg["epoch"], pkg["version"], pkg["release"])
            fin = {
                "Name": pkg["name"],
                "NamespaceName": namespace,
                "VersionFormat": "rpm",
                "Version": version,
                "Module": module_info,
                "VendorAdvisory": vendor_advisory,
            }

            # check if the currently processed fixed in record for a
            # given package name is present and has a version less
            # than what has already been processed, if so skip and if
            # not, store as the 'latest' fixed in

            if pkg["name"] in fins and utils.rpm.compare_versions(version, fins[pkg["name"]]["Version"]) <= 0:
                continue
            fins[pkg["name"]] = fin

        return list(fins.values())

    def parse_alma_record(self, input_record, namespace):
        vid = input_record.get("updateinfo_id", None)
        in_description = input_record.get("description", "")
        in_type = input_record.get("type", "")
        in_severity = input_record.get("severity", "none")
        in_refs = input_record.get("references", [])
        in_module_name = input_record.get("pkglist", {}).get("module", {}).get("name", "")
        in_module_version = input_record.get("pkglist", {}).get("module", {}).get("stream", "")
        in_pkgs = input_record.get("pkglist", {}).get("packages", [])
        input_record.get("description", "")

        if not vid or in_type != "security":
            return {}

        severity = self._parse_severity(in_severity)

        link, cves = self._parse_linkrefs(in_refs, vid=vid, namespace=namespace)

        module_info = self._parse_moduleinfo(in_module_name, in_module_version)

        vendor_advisory = self._parse_vendor_advisory(vid, link)

        fixed_ins = self._parse_fixed_ins(in_pkgs, namespace, module_info, vendor_advisory)

        # TODO - maybe craft a metadata that has a few CVE: [{Name:
        # CVE-1234, Link: ...}, {Name: ALSA-123:123, Link:
        # almaerrata/ALSA-123-123.html}] records?

        vidmap = {}
        for cve in cves:
            vid = cve
            v = Vulnerability(
                Name=vid,
                NamespaceName=namespace,
                Description=in_description,
                Severity=severity,
                Link=link,
                CVSS=[],
                FixedIn=fixed_ins,
                Metadata={},
            )
            vidmap[vid] = v

        return vidmap
