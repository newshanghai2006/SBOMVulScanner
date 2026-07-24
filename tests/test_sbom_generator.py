import asyncio
from pathlib import Path
from zipfile import ZipFile

import pytest

from app.sbom_generator import (
    GenerationError,
    clone_repository,
    ensure_git_host_allowed,
    extract_zip,
    parse_git_clone,
)


def test_parse_supported_git_clone_command():
    source = parse_git_clone(
        "git clone -b release --single-branch http://10.1.1.1:3000/group/device-center.git"
    )

    assert source.url == "http://10.1.1.1:3000/group/device-center.git"
    assert source.host == "10.1.1.1"
    assert source.branch == "release"


def test_git_host_requires_explicit_allowlist(monkeypatch):
    source = parse_git_clone("git clone https://git.example.com/group/project.git")
    monkeypatch.delenv("SBOM_GIT_ALLOWED_HOSTS", raising=False)
    with pytest.raises(GenerationError, match="未被服务器管理员允许"):
        ensure_git_host_allowed(source)

    monkeypatch.setenv("SBOM_GIT_ALLOWED_HOSTS", "10.1.1.1,git.example.com")
    ensure_git_host_allowed(source)


def test_clone_credentials_are_not_added_to_command_line(monkeypatch, tmp_path: Path):
    source = parse_git_clone("git clone https://git.example.com/group/project.git")
    monkeypatch.setenv("SBOM_GIT_ALLOWED_HOSTS", "git.example.com")
    monkeypatch.setattr("app.sbom_generator.shutil.which", lambda _name: "/usr/bin/git")

    async def fake_run(*args, timeout, env=None):
        assert timeout == 300
        assert "secret-token" not in args
        assert "credential.helper=" in args
        assert env["GIT_TERMINAL_PROMPT"] == "0"
        assert env["GCM_INTERACTIVE"] == "Never"
        assert env["SBOM_SCAN_GIT_USERNAME"] == "build-user"
        assert env["SBOM_SCAN_GIT_PASSWORD"] == "secret-token"
        Path(args[-1]).mkdir()
        return 0, b"", b""

    monkeypatch.setattr("app.sbom_generator._run_process", fake_run)
    destination = tmp_path / "source"
    asyncio.run(clone_repository(source, destination, "build-user", "secret-token"))

    assert destination.exists()
    assert not (tmp_path / "git-askpass.py").exists()


@pytest.mark.parametrize("command", [
    "git clone --upload-pack=/tmp/tool https://example.com/repo.git",
    "git clone https://example.com/repo.git destination",
    "sh -c 'git clone https://example.com/repo.git'",
    "git clone file:///etc",
])
def test_reject_unsafe_git_clone_commands(command):
    with pytest.raises(GenerationError):
        parse_git_clone(command)


def test_extract_zip_rejects_path_traversal(tmp_path: Path):
    archive = tmp_path / "source.zip"
    with ZipFile(archive, "w") as output:
        output.writestr("../outside.txt", "blocked")

    with pytest.raises(GenerationError, match="outside"):
        extract_zip(archive, tmp_path / "source")
    assert not (tmp_path / "outside.txt").exists()


def test_extract_zip_extracts_regular_files(tmp_path: Path):
    archive = tmp_path / "source.zip"
    with ZipFile(archive, "w") as output:
        output.writestr("project/requirements.txt", "fastapi==0.116.1")

    destination = tmp_path / "source"
    extract_zip(archive, destination)

    assert (destination / "project" / "requirements.txt").read_text() == "fastapi==0.116.1"
