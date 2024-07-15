from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

import requests

from vunnel import utils
from vunnel.utils.vulnerability import FixedIn, Vulnerability

if TYPE_CHECKING:
    import logging
    from collections.abc import Generator

    from vunnel.workspace import Workspace

# TODO: investigate the 'module' mappings, seeing some partial/odd
# elements in the data and need to verify the final implications (in
# particular when reporting fixed versions across modules)

# TODO: re-visit possible error paths / bailouts in the parser to
# guarantee progress and proper instructive/useful warnings

# TODO: re-visit record gets defaulting to either "" or None, align
# with expectations of the resulting OS schema

NAMESPACE = "almalinux"
ALMALINUX_URL_BASE = "https://errata.almalinux.org/{}/errata.full.json"
#ALMALINUX_URL_BASE = "https://errata.almalinux.org/{}/errata.json"


class Parser:
    #    def __init__(self, workspace, download_timeout, allow_versions, logger):
    def __init__(self, workspace: Workspace, download_timeout: int, allow_versions: list[Any], logger: logging.Logger):
        self.workspace = workspace
        self.download_timeout = download_timeout
        self.allow_versions = allow_versions
        self.urls: list[str] = []
        self.logger = logger

    def _download(self) -> list[tuple[str, str]]:
        # TODO - check for last version + 1, based on config?
        return [self._download_version(v) for v in self.allow_versions]

    def _download_version(self, version: str) -> tuple[str, str]:
        localfilename = f"almalinux_{version}.json"
        namespace = f"almalinux:{version}"
        url = ALMALINUX_URL_BASE.format(version)
        r = requests.get(url, timeout=self.download_timeout)
        destination = os.path.join(self.workspace.input_path, localfilename)
        with open(destination, "wb") as writer:
            writer.write(r.content)
        return destination, namespace

    def get(self) -> Generator[tuple[str, str, dict[str, dict[str, Any]]], None, None]:
        for local_file_path, namespace in self._download():
            with open(local_file_path) as FH:
                alma_records = json.loads(FH.read()).get('data', [])

            # TODO: consider adding an alma record schema check, here

            for alma_record in alma_records:
                #print (alma_record)

                try:
                    vidmap = self.parse_alma_record(alma_record, namespace)
                    for vid in vidmap:
                        yield namespace, vid, vidmap[vid].to_payload()
                except Exception as err:
                    self.logger.warning(f"skipping alma record - exception: {err}")

    def _parse_severity(self, in_severity: str) -> str:
        severity_dict = {
            "none": "Unknown",
            "low": "Low",
            "moderate": "Medium",
            "important": "High",
            "critical": "Critical",
        }
        return severity_dict[in_severity.lower()]

    def _parse_linkrefs(self, in_refs: list[dict[str, str]], vid: str, namespace: str) -> tuple[str, list[str]]:
        cves = []
        link = ""
        for ref in in_refs:
            reftype = ref.get("type", "")
            reflink = ref.get("href", "")
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

    def _parse_moduleinfo(self, in_module_name: str, in_module_version: str) -> str | None:
        module_info = None
        if in_module_name:
            module_info = in_module_name
            if in_module_version:
                module_info += f":{in_module_version}"

        return module_info

    def _parse_vendor_advisory(self, vid: str, link: str | None) -> dict[str, Any]:
        wont_fix = False
        vendor_advisory = {
            "NoAdvisory": False,
            "AdvisorySummary": [],
        }

        if wont_fix:
            vendor_advisory["NoAdvisory"] = True
        elif vid and link:
            el = {
                "ID": vid,
                "Link": link,
            }
            vendor_advisory["AdvisorySummary"] = [el]

        return vendor_advisory

    def _parse_fixed_ins(
        self,
        in_pkgs: list[dict[str, Any]],
        namespace: str,
        #module_info: str | None,
        vendor_advisory: dict[str, Any],
    ) -> list[FixedIn]:
        fins = {}  # type: dict[str,Any]
        for pkg in in_pkgs:
            #print(pkg)
            if pkg.get("arch", "") not in ["x86_64", "noarch"]:
                continue

            version = "{}:{}-{}".format(pkg["epoch"], pkg["version"], pkg["release"])
            
            module_info = pkg.get("module", None)
            if not module_info:
                # handles when module is set but is blank/empty types lime "" and [], seen in some cases
                module_info = None
            
            fin = FixedIn(
                Name=pkg["name"],
                NamespaceName=namespace,
                VersionFormat="rpm",
                Version=version,
                Module=module_info,
                VendorAdvisory=vendor_advisory,
            )

            # check if the currently processed fixed in record for a
            # given package name is present and has a version less
            # than what has already been processed, if so skip and if
            # not, store as the 'latest' fixed in

            if pkg["name"] in fins and utils.rpm.compare_versions(version, fins[pkg["name"]].Version) <= 0:
                continue
            fins[pkg["name"]] = fin

        return list(fins.values())

    def parse_alma_record(self, input_record: dict[str, Any], namespace: str) -> dict[str, Vulnerability]:
        vid = input_record.get("id", None)
        in_description = input_record.get("description", "")
        in_type = input_record.get("type", "")
        in_severity = input_record.get("severity", "none")
        in_refs = input_record.get("references", [])
        #in_modules = input_record.get('modules', [])
        in_pkgs = input_record.get("packages", [])
        input_record.get("description", "")

        # quick check to make sure this is a security advisory and has a name
        if not vid or in_type != "security":
            return {}

        # parse out all the input into what we need for processing / setup into an OS Schema record

        severity = self._parse_severity(in_severity)

        link, cves = self._parse_linkrefs(in_refs, vid, namespace)

        #module_info = self._parse_moduleinfo(in_modules)

        vendor_advisory = self._parse_vendor_advisory(vid, link)

        #fixed_ins = self._parse_fixed_ins(in_pkgs, namespace, module_info, vendor_advisory)        
        fixed_ins = self._parse_fixed_ins(in_pkgs, namespace, vendor_advisory)

        # construct the final set of OS schema records

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
