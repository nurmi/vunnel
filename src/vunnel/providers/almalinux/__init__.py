from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema

from .parser import Parser

if TYPE_CHECKING:
    import datetime

PROVIDER_NAME = "almalinux"
SCHEMA = schema.OSSchema()

@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=provider.ResultStatePolicy.DELETE,
        ),
    )
    request_timeout: int = 125
    allow_versions: list[str] = field(default_factory=lambda: ["8", "9"])
    guess_next_version: bool = True


class Provider(provider.Provider):
    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()

        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config
        self.logger.debug(f"config: {config}")

        self.parser = Parser(
            workspace=self.workspace,
            download_timeout=self.config.request_timeout,
            allow_versions=self.config.allow_versions,
            logger=self.logger,
        )

    @classmethod
    def name(cls) -> str:
        return PROVIDER_NAME

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with self.results_writer() as writer:
            for namespace, vuln_id, record in self.parser.get():
                writer.write(
                    identifier=os.path.join(namespace, vuln_id),
                    schema=SCHEMA,
                    payload=record,
                )

        return self.parser.urls, len(writer)
