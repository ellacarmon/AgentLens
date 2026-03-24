from agentlens.core.fetcher import Fetcher
from agentlens.core.ingestion import Target


def test_npm_scan_resolves_package_version(monkeypatch, tmp_path):
    target = Target("npm:left-pad")
    fetcher = Fetcher(target)

    def fake_http_get_json(url):
        assert url.endswith("/left-pad")
        return {
            "dist-tags": {"latest": "1.3.0"},
            "versions": {
                "1.3.0": {
                    "dist": {"tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}
                }
            },
        }

    monkeypatch.setattr("agentlens.core.fetcher._http_get_json", fake_http_get_json)
    monkeypatch.setattr("agentlens.core.fetcher._http_download", lambda url, dest: tmp_path.joinpath("npm").write_text("x"))
    monkeypatch.setattr("agentlens.core.fetcher.extract_tar_archive", lambda artifact, staging: None)

    fetcher._fetch_npm_registry()

    assert fetcher.resolved_package_name == "left-pad"
    assert fetcher.resolved_package_version == "1.3.0"


def test_npm_scan_uses_requested_package_version(monkeypatch, tmp_path):
    target = Target("npm:left-pad@1.1.3")
    fetcher = Fetcher(target)

    def fake_http_get_json(url):
        assert url.endswith("/left-pad")
        return {
            "dist-tags": {"latest": "1.3.0"},
            "versions": {
                "1.1.3": {
                    "dist": {"tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.1.3.tgz"}
                },
                "1.3.0": {
                    "dist": {"tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}
                },
            },
        }

    monkeypatch.setattr("agentlens.core.fetcher._http_get_json", fake_http_get_json)
    monkeypatch.setattr("agentlens.core.fetcher._http_download", lambda url, dest: tmp_path.joinpath("npm-pinned").write_text("x"))
    monkeypatch.setattr("agentlens.core.fetcher.extract_tar_archive", lambda artifact, staging: None)

    fetcher._fetch_npm_registry()

    assert fetcher.resolved_package_name == "left-pad"
    assert fetcher.resolved_package_version == "1.1.3"


def test_pypi_scan_resolves_package_version(monkeypatch, tmp_path):
    target = Target("pypi:requests")
    fetcher = Fetcher(target)

    def fake_http_get_json(url):
        assert url.endswith("/requests/json")
        return {
            "info": {"version": "2.32.5"},
            "urls": [
                {
                    "packagetype": "sdist",
                    "filename": "requests-2.32.5.tar.gz",
                    "url": "https://files.pythonhosted.org/packages/source/r/requests/requests-2.32.5.tar.gz",
                }
            ],
        }

    monkeypatch.setattr("agentlens.core.fetcher._http_get_json", fake_http_get_json)
    monkeypatch.setattr("agentlens.core.fetcher._http_download", lambda url, dest: tmp_path.joinpath("pypi").write_text("x"))
    monkeypatch.setattr("agentlens.core.fetcher.extract_tar_archive", lambda artifact, staging: None)

    fetcher._fetch_pypi_registry()

    assert fetcher.resolved_package_name == "requests"
    assert fetcher.resolved_package_version == "2.32.5"


def test_pypi_scan_uses_requested_package_version(monkeypatch, tmp_path):
    target = Target("pypi:requests==2.31.0")
    fetcher = Fetcher(target)

    def fake_http_get_json(url):
        assert url.endswith("/requests/2.31.0/json")
        return {
            "info": {"version": "2.31.0"},
            "urls": [
                {
                    "packagetype": "sdist",
                    "filename": "requests-2.31.0.tar.gz",
                    "url": "https://files.pythonhosted.org/packages/source/r/requests/requests-2.31.0.tar.gz",
                }
            ],
        }

    monkeypatch.setattr("agentlens.core.fetcher._http_get_json", fake_http_get_json)
    monkeypatch.setattr("agentlens.core.fetcher._http_download", lambda url, dest: tmp_path.joinpath("pypi-pinned").write_text("x"))
    monkeypatch.setattr("agentlens.core.fetcher.extract_tar_archive", lambda artifact, staging: None)

    fetcher._fetch_pypi_registry()

    assert fetcher.resolved_package_name == "requests"
    assert fetcher.resolved_package_version == "2.31.0"


def test_clawhub_scan_resolves_skill_version(monkeypatch, tmp_path):
    target = Target("clawhub:calendar-helper")
    fetcher = Fetcher(target)

    def fake_http_get_json(url):
        assert url.endswith("/api/v1/skills/calendar-helper")
        return {
            "skill": {"slug": "calendar-helper", "displayName": "Calendar Helper"},
            "latestVersion": {"version": "1.4.2"},
        }

    download_calls = []

    def fake_http_download(url, dest):
        download_calls.append((url, dest))
        tmp_path.joinpath("clawhub").write_text("x")

    monkeypatch.setattr("agentlens.core.fetcher._http_get_json", fake_http_get_json)
    monkeypatch.setattr("agentlens.core.fetcher._http_download", fake_http_download)
    monkeypatch.setattr("agentlens.core.fetcher.extract_zip_archive", lambda artifact, staging: None)

    fetcher._fetch_clawhub_registry()

    assert fetcher.resolved_package_name == "calendar-helper"
    assert fetcher.resolved_package_version == "1.4.2"
    assert download_calls == [
        (
            "https://clawhub.ai/api/v1/download?slug=calendar-helper&version=1.4.2",
            download_calls[0][1],
        )
    ]


def test_clawhub_scan_uses_requested_skill_version(monkeypatch, tmp_path):
    target = Target("clawhub:calendar-helper@1.2.0")
    fetcher = Fetcher(target)

    def fake_http_get_json(url):
        assert url.endswith("/api/v1/skills/calendar-helper")
        return {
            "skill": {"slug": "calendar-helper", "displayName": "Calendar Helper"},
            "latestVersion": {"version": "1.4.2"},
        }

    download_calls = []

    def fake_http_download(url, dest):
        download_calls.append((url, dest))
        tmp_path.joinpath("clawhub-pinned").write_text("x")

    monkeypatch.setattr("agentlens.core.fetcher._http_get_json", fake_http_get_json)
    monkeypatch.setattr("agentlens.core.fetcher._http_download", fake_http_download)
    monkeypatch.setattr("agentlens.core.fetcher.extract_zip_archive", lambda artifact, staging: None)

    fetcher._fetch_clawhub_registry()

    assert fetcher.resolved_package_name == "calendar-helper"
    assert fetcher.resolved_package_version == "1.2.0"
    assert download_calls == [
        (
            "https://clawhub.ai/api/v1/download?slug=calendar-helper&version=1.2.0",
            download_calls[0][1],
        )
    ]
