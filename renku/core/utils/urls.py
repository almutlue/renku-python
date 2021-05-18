# -*- coding: utf-8 -*-
#
# Copyright 2020 - Swiss Data Science Center (SDSC)
# A partnership between École Polytechnique Fédérale de Lausanne (EPFL) and
# Eidgenössische Technische Hochschule Zürich (ETHZ).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Helpers utils for handling URLs."""

import os
import re
import unicodedata
import urllib
from urllib.parse import ParseResult

from renku.core import errors

_URL_VALIDATOR = r"[^\w\-.~:/?#\[\]@!$&'\(\)\*\+,;=]+"


def url_to_string(url):
    """Convert url from ``list`` or ``ParseResult`` to string."""
    if isinstance(url, list):
        return ParseResult(scheme=url[0], netloc=url[1], path=url[2], params=None, query=None, fragment=None,).geturl()

    if isinstance(url, ParseResult):
        return url.geturl()

    if isinstance(url, str):
        return url

    raise ValueError("url value not recognized")


def remove_credentials(url):
    """Remove username and password from a URL."""
    if url is None:
        return ""
    parsed = urllib.parse.urlparse(url)
    return parsed._replace(netloc=parsed.hostname).geturl()


def get_host(client):
    """Return the hostname for the resource URIs.

    Default is localhost. If RENKU_DOMAIN is set, it overrides the host from remote.
    """
    host = "localhost"

    if client:
        host = client.remote.get("host") or host

    return os.environ.get("RENKU_DOMAIN") or host


def parse_authentication_endpoint(client, endpoint, use_remote=False):
    """Return a parsed url.

    If an endpoint is provided then use it, otherwise, look for a configured endpoint. If no configured endpoint exists
    then try to use project's remote url.
    """
    if not endpoint:
        endpoint = client.get_value(section="renku", key="endpoint")
        if not endpoint:
            if not use_remote:
                return
            remote_url = get_remote(client.repo)
            if not remote_url:
                return
            endpoint = f"https://{validate_url(remote_url, enforce_remote=True).netloc}/"

    if not endpoint.startswith("http"):
        endpoint = f"https://{endpoint}"

    parsed_endpoint = urllib.parse.urlparse(endpoint)
    if not parsed_endpoint.netloc:
        raise errors.ParameterError(f"Invalid endpoint: `{endpoint}`.")

    return parsed_endpoint._replace(scheme="https", path="/", params="", query="", fragment="")


def get_remote(repo):
    """Return remote url of repo or its active branch."""
    if not repo or not repo.remotes:
        return
    elif len(repo.remotes) == 1:
        return repo.remotes[0].url
    elif repo.active_branch.tracking_branch():
        return repo.remotes[repo.active_branch.tracking_branch().remote_name].url


def get_slug(name):
    """Create a slug from name."""
    lower_case = name.lower()
    no_space = re.sub(r"\s+", "_", lower_case)
    normalized = unicodedata.normalize("NFKD", no_space).encode("ascii", "ignore").decode("utf-8")
    no_invalid_characters = re.sub(r"[^a-zA-Z0-9._-]", "_", normalized)
    no_duplicates = re.sub(r"([._-])[._-]+", r"\1", no_invalid_characters)
    valid_start = re.sub(r"^[._-]", "", no_duplicates)
    valid_end = re.sub(r"[._-]$", "", valid_start)
    no_dot_lock_at_end = re.sub(r"\.lock$", "_lock", valid_end)
    return no_dot_lock_at_end


def validate_url(repo: str, enforce_remote: bool = False) -> ParseResult:
    """Validates the supplied url and returns the parsed URL if valid."""
    if re.search(_URL_VALIDATOR, repo, re.ASCII):
        raise errors.ParameterError(f"Invalid url: `{repo}`")
    parsed_url = urllib.parse.urlparse(repo)
    if enforce_remote and len(parsed_url.netloc) == 0:
        raise errors.ParameterError(f"Not a remote url: `{repo}`")
    return parsed_url
