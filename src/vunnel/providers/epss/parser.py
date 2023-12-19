from __future__ import annotations

import json
import logging
import os

import requests

from vunnel import utils, workspace

NAMESPACE = "epss"


class Parser:
    # this provider is 'basic functionality' to just encode the getting of EPSS data by exercising the public API (see https://api.first.org/epss/)
    # using JSON lines (https://jsonlines.org/) for storing downloaded data in order to efficiently stream, for now
    _json_url_ = "https://api.first.org/data/v1/epss"
    _json_file_ = "epss_data.jsonl"

    def __init__(self, ws: workspace.Workspace, download_timeout: int = 125, logger: logging.Logger | None = None):
        self.workspace = ws
        self.download_timeout = download_timeout
        self.json_file_path = os.path.join(ws.input_path, self._json_file_)
        self.urls = [self._json_url_]

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def get(self):
        self._download()
        yield from self._normalize()

    @utils.retry_with_backoff()
    def _download(self):
        self.logger.info(f"EPSS data download starting")        
        limit = 10000
        offset = 0
        current = 0
        
        params = {'limit': limit, 'offset': offset}
        self.logger.info(f"downloading EPSS data from {self._json_url_} with params {params}")

        r = requests.get(self._json_url_, params=params, timeout=self.download_timeout)
        r.raise_for_status()
        total = r.json().get("total", 0)
        total = 20000       # for debugging - set this to limit the total number fetched
        with open(self.json_file_path, "w", encoding="utf-8") as f:
            done = False
            while not done:
                for record in r.json().get('data', []):
                    f.write(json.dumps(record) + "\n")
                    
                current = current + limit
                if current >= total:
                    done = True
                else:
                    offset = offset + limit

                    params = {'limit': limit, 'offset': offset}
                    self.logger.info(f"downloading EPSS data from {self._json_url_} with params {params}")
                    
                    r = requests.get(self._json_url_, params=params, timeout=self.download_timeout)
                    r.raise_for_status()
        self.logger.info(f"EPSS data download completed")
        
    def _normalize(self):
        self.logger.info(f"EPSS data normalizing starting - processing JSON lines from {self.json_file_path}")
        count=0
        with open(self.json_file_path, encoding="utf-8") as f:
            for line in f.readlines():
                count = count + 1
                if count % 5000 == 0:
                    self.logger.info(f"normalizing EPSS data, processed {count} records")
                input_record = json.loads(line)
                if not input_record:
                    continue
                yield input_record.get("cve"), input_record
        self.logger.info(f"EPSS data normalizing completed")
