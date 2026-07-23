from pathlib import Path
from zipfile import ZipFile

import pytest

from app.sbom_generator import GenerationError, ensure_git_host_allowed, extract_zip, parse_git_clone


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
    with pytest.raises(GenerationError, match="not allowed"):
        ensure_git_host_allowed(source)

    monkeypatch.setenv("SBOM_GIT_ALLOWED_HOSTS", "10.1.1.1,git.example.com")
    ensure_git_host_allowed(source)


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
