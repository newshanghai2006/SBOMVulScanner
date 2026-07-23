from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import shutil
import signal
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


MAX_ARCHIVE_SIZE = 100 * 1024 * 1024
MAX_EXTRACTED_SIZE = 500 * 1024 * 1024
MAX_SOURCE_FILES = 20_000
MAX_SBOM_SIZE = 100 * 1024 * 1024
BRANCH_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
SCP_GIT_PATTERN = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[^\s]+$")


class GenerationError(ValueError):
    pass


@dataclass(frozen=True)
class GitSource:
    url: str
    host: str
    branch: str | None = None


def syft_available() -> bool:
    return shutil.which(os.environ.get("SYFT_PATH", "syft")) is not None


def _git_host(url: str) -> str:
    if SCP_GIT_PATTERN.fullmatch(url):
        return url.split("@", 1)[1].split(":", 1)[0].lower()
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https", "ssh", "git"} or not parsed.hostname:
        raise GenerationError("Repository URL must use http, https, ssh, or git")
    if parsed.password:
        raise GenerationError("Do not put passwords in the repository URL; configure credentials for the service account")
    return parsed.hostname.lower()


def parse_git_clone(command: str) -> GitSource:
    if not command or len(command) > 4096 or any(char in command for char in "\r\n\0"):
        raise GenerationError("A single git clone command is required")
    try:
        parts = shlex.split(command, posix=True)
    except ValueError as exc:
        raise GenerationError("Invalid git clone command quoting") from exc
    if parts[:2] != ["git", "clone"]:
        raise GenerationError("Only git clone commands are accepted")

    branch: str | None = None
    url: str | None = None
    index = 2
    while index < len(parts):
        token = parts[index]
        if token in {"-b", "--branch"}:
            index += 1
            if index >= len(parts):
                raise GenerationError(f"{token} requires a branch name")
            branch = parts[index]
        elif token.startswith("--branch="):
            branch = token.split("=", 1)[1]
        elif token == "--single-branch":
            pass
        elif token == "--":
            index += 1
            if index >= len(parts) or url is not None:
                raise GenerationError("Repository URL is missing")
            url = parts[index]
        elif token.startswith("-"):
            raise GenerationError(f"Unsupported git clone option: {token}")
        elif url is None:
            url = token
        else:
            raise GenerationError("A destination directory is not accepted; the server creates an isolated directory")
        index += 1

    if not url:
        raise GenerationError("Repository URL is missing")
    if len(url) > 2048:
        raise GenerationError("Repository URL is too long")
    if branch and (not BRANCH_PATTERN.fullmatch(branch) or ".." in branch):
        raise GenerationError("Branch name contains unsupported characters")
    return GitSource(url=url, host=_git_host(url), branch=branch)


def ensure_git_host_allowed(source: GitSource) -> None:
    allowed = {item.strip().lower() for item in os.environ.get("SBOM_GIT_ALLOWED_HOSTS", "").split(",") if item.strip()}
    if source.host not in allowed:
        raise GenerationError(
            f"Repository host '{source.host}' is not allowed; add it to SBOM_GIT_ALLOWED_HOSTS and restart the service"
        )


def extract_zip(archive: Path, destination: Path) -> None:
    try:
        with zipfile.ZipFile(archive) as source:
            members = source.infolist()
            if len(members) > MAX_SOURCE_FILES:
                raise GenerationError(f"ZIP contains more than {MAX_SOURCE_FILES} entries")
            total_size = 0
            root = destination.resolve()
            for member in members:
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise GenerationError("ZIP symbolic links are not allowed")
                total_size += member.file_size
                if total_size > MAX_EXTRACTED_SIZE:
                    raise GenerationError("ZIP extracted size exceeds 500 MB")
                target = (destination / member.filename).resolve()
                if target != root and root not in target.parents:
                    raise GenerationError("ZIP contains a path outside its root")
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.open(member) as incoming, target.open("wb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing, length=1024 * 1024)
    except zipfile.BadZipFile as exc:
        raise GenerationError("Uploaded file is not a valid ZIP archive") from exc


def validate_source_tree(root: Path) -> None:
    count = 0
    total_size = 0
    for path in root.rglob("*"):
        if path.is_symlink():
            raise GenerationError("Source symbolic links are not allowed")
        if path.is_file():
            count += 1
            total_size += path.stat().st_size
            if count > MAX_SOURCE_FILES:
                raise GenerationError(f"Source contains more than {MAX_SOURCE_FILES} files")
            if total_size > MAX_EXTRACTED_SIZE:
                raise GenerationError("Source size exceeds 500 MB")


async def _run_process(*args: str, timeout: int) -> tuple[int, bytes, bytes]:
    try:
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=os.name != "nt",
        )
    except OSError as exc:
        raise GenerationError(f"Unable to start required command: {Path(args[0]).name}") from exc
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        return process.returncode, stdout, stderr
    except TimeoutError:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        await process.communicate()
        raise GenerationError(f"Command timed out after {timeout} seconds")


async def clone_repository(source: GitSource, destination: Path) -> None:
    ensure_git_host_allowed(source)
    git = shutil.which(os.environ.get("GIT_PATH", "git"))
    if not git:
        raise GenerationError("Git is not installed on the server")
    args = [git, "clone", "--depth", "1", "--single-branch"]
    if source.branch:
        args.extend(["--branch", source.branch])
    args.extend(["--", source.url, str(destination)])
    returncode, stdout, stderr = await _run_process(*args, timeout=300)
    del stdout, stderr
    if returncode != 0 or not destination.exists():
        raise GenerationError("Git clone failed; verify the URL, branch, network, and service-account credentials")
    shutil.rmtree(destination / ".git", ignore_errors=True)
    validate_source_tree(destination)


async def generate_sbom(source: Path, output_format: str) -> bytes:
    formats = {"cyclonedx": "cyclonedx-json", "spdx": "spdx-json"}
    if output_format not in formats:
        raise GenerationError("Output format must be cyclonedx or spdx")
    syft = shutil.which(os.environ.get("SYFT_PATH", "syft"))
    if not syft:
        raise GenerationError("Syft is not installed on the server")
    returncode, stdout, stderr = await _run_process(
        syft, "scan", f"dir:{source}", "--output", formats[output_format], "--quiet", timeout=600,
    )
    if returncode != 0 or not stdout:
        del stderr
        raise GenerationError("Syft failed to generate an SBOM")
    if len(stdout) > MAX_SBOM_SIZE:
        raise GenerationError("Generated SBOM exceeds 100 MB")
    try:
        document = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise GenerationError("Syft returned invalid JSON") from exc
    if output_format == "cyclonedx" and document.get("bomFormat") != "CycloneDX":
        raise GenerationError("Syft did not return a CycloneDX document")
    if output_format == "spdx" and not str(document.get("spdxVersion", "")).startswith("SPDX-"):
        raise GenerationError("Syft did not return an SPDX document")
    return json.dumps(document, ensure_ascii=False, indent=2).encode("utf-8")
