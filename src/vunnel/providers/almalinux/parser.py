from __future__ import annotations

import copy
import json
import logging
import os

import requests

from collections import namedtuple

from vunnel import utils, workspace
from vunnel.utils import vulnerability
from vunnel.utils.vulnerability import Vulnerability, FixedIn

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
    def __init__(self, workspace: Workspace, download_timeout: int, allow_versions: list[Any], logger: logging.Logger):
        self.workspace = workspace
        self.download_timeout = download_timeout
        self.allow_versions = allow_versions
        self.urls: list[str] = []
        self.logger = logger

    def _download(self) -> list[str]:
        # TODO - check for last version + 1, based on config?
        return [self._download_version(v) for v in self.allow_versions]

    def _download_version(self, version: str) -> str:
        localfilename = "almalinux_{}.json".format(version)
        namespace = "almalinux:{}".format(version)
        url = ALMALINUX_URL_BASE.format(version)
        r = requests.get(url, timeout=self.download_timeout)
        destination = os.path.join(self.workspace.input_path, localfilename)
        with open(destination, "wb") as writer:
            writer.write(r.content)
        return destination, namespace

    def get(self):
        for local_file_path,namespace in self._download():
            with open(local_file_path, 'r') as FH:
                alma_records = json.loads(FH.read())

            # TODO: consider adding an alma record schema check, here
            
            for alma_record in alma_records:
                try:
                    vidmap = self.parse_alma_record(alma_record, namespace)
                    for vid in vidmap.keys():
                        yield namespace, vid, vidmap[vid].to_payload()
                except Exception as err:
                    self.logger.warning("skipping alma record - exception: {}".format(err))

    def parse_alma_record(self, input, namespace):
        if input.get('type', "") != 'security':
            return {}
        
        vid = input.get('updateinfo_id', None)

        severity_dict = {
            "none": "Unknown",
            "low": "Low",
            "moderate": "Medium",
            "important": "High",
            "critical": "Critical",
        }
        severity = severity_dict[input.get('severity', 'none').lower()]

        cves = []
        metadata = {
            "CVE": [],
        }
        link = None
        for ref in input.get('references', []):
            reftype = ref.get('type', "")
            reflink = ref.get('href', None)
            refid = ref.get('id', None)
            
            if reftype == 'self':
                link = reflink
            elif reftype == 'cve':
                if refid:
                    cves.append(refid)
                    if reflink:
                        metadata['CVE'].append(
                            {
                                'Name': refid,
                                'Link': reflink,
                            }
                        )
                        
        if link == None:
            # handle case where the self link isn't set (seen in some records) - construct a
            #
            # https://errata.almalinux.org/8/ALSA-2021-4154.html
            #
            # url from an ALSA-2021:4154 vid
            #
            try:
                nsname, nsvers = namespace.split(":", 1)
            
                html = "{}.html".format(vid)
                pre,post = vid.split(":", 1)
                if pre and post:
                    html = "{}-{}.html".format(pre,post)                
                link = "https://errata.almalinux.org/{}/{}".format(nsvers, html)
            except Exception as err:
                self.logger.warning("self link not set for vulnerability {}, leaving link null.  exception: {}".format(vid, err))
                
        module_info = None
        module_name = input.get('pkglist', {}).get('module', {}).get('name', "")
        module_version = input.get('pkglist', {}).get('module', {}).get('stream', "")
        if module_name:
            module_info = module_name
            if module_version:
                module_info = "{}:{}".format(module_name, module_version)

        wont_fix = False
        vendor_advisory = {"NoAdvisory": False, "AdvisorySummary": []}
        if wont_fix:
            vendor_advisory = {"NoAdvisory": True}
        else:
            if vid and link:
                vendor_advisory["AdvisorySummary"].append(
                    {
                        "ID": vid,
                        "Link": link,
                    }
                )
                
        fins = {}
        for pkg in input.get('pkglist', {}).get('packages', []):
            if pkg['arch'] not in ['x86_64', 'noarch']:
                continue

            version = "{}:{}-{}".format(pkg['epoch'], pkg['version'], pkg['release'])
            fin = {
                "Name":pkg['name'],
                "NamespaceName":namespace,
                "VersionFormat":"rpm",
                "Version":version,
                "Module":module_info,
                "VendorAdvisory":vendor_advisory,
            }

            # check if the currently processed fixed in record for a given package name is present and has a version less than what has already been processed, if so skip and if not, store as the 'latest' fixed in
            if pkg['name'] in fins and utils.rpm.compare_versions(version, fins[pkg['name']]['Version']) <= 0:
                continue
            else:
                fins[pkg['name']] = fin                

        fixed_ins = list(fins.values())

        # TODO - maybe craft a metadata that has a few CVE: [{Name: CVE-1234, Link: ...}, {Name: ALSA-123:123, Link: almaerrata/ALSA-123-123.html}] records?
        vidmap = {}        
        for cve in cves:
            vid = cve
            v = Vulnerability(
                Name=vid,
	        NamespaceName=namespace,
	        Description=input.get('description', ""),
	        Severity=severity,
                Link=link,
	        CVSS=[],
	        FixedIn=fixed_ins,
                Metadata={},
            )
            vidmap[vid] = v

        return(vidmap)
