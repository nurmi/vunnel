from __future__ import annotations

import copy
import json
import logging
import os

import requests
from vunnel import utils, workspace
from vunnel.utils import vulnerability
from vunnel.utils.vulnerability import FixedIn, Vulnerability

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
                
            # TODO - could perform a schema check here
            
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
            # TODO handle case where the self link isn't set (seen in some records) - construct a
            #
            # https://errata.almalinux.org/8/ALSA-2021-4154.html
            #
            # url from an ALSA-2021:4154 vid
            #
            pass

        vidmap = {}

        # TODO - observed that there are multiple versions for same
        # package in the pkglist, need to keep track of the 'latest'
        # and only create a fixedin record for that
        
        fixed_ins = []
        for pkg in input.get('pkglist', {}).get('packages', []):
            version = "{}:{}-{}".format(pkg['epoch'], pkg['version'], pkg['release'])
            fin = FixedIn(
                Name=pkg['name'],
                NamespaceName=namespace,
                VersionFormat="rpm",
                Version=version,
            )
            fixed_ins.append(fin)

        # TODO - maybe craft a metadata that has a few CVE: [{Name: CVE-1234, Link: ...}, {Name: ALSA-123:123, Link: almaerrata/ALSA-123-123.html}] records?
        # TODO - CVSS populated for this type of vuln?
        
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
