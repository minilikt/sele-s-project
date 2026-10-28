"""Import API and incident enrichment tests."""

from __future__ import annotations

import json

from test_evtx_import import make_xml


def upload(client, name, content, **params):
    return client.post(
        "/api/events/import",
        files={"file": (name, content, "application/octet-stream")},
        params=params,
    )


class TestImportEndpoint:
    def test_imports_xml(self, client):
        response = upload(client, "security.xml", make_xml().encode("utf-8"))
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["imported"] == 1
        assert body["format"] == "xml"
        assert client.get("/api/events").json()["total"] == 1

    def test_reimport_is_deduplicated(self, client):
        upload(client, "security.xml", make_xml().encode("utf-8"))
        second = upload(client, "security.xml", make_xml().encode("utf-8")).json()
        assert second["imported"] == 0
        assert second["duplicates"] == 1
        assert client.get("/api/events").json()["total"] == 1

    def test_dry_run_does_not_persist(self, client):
        body = upload(client, "security.xml", make_xml().encode("utf-8"), dry_run=True).json()
        assert body["parsed"] == 1
        assert body["imported"] == 0
        assert len(body["preview"]) == 1
        assert client.get("/api/events").json()["total"] == 0

    def test_empty_file_rejected(self, client):
        response = upload(client, "empty.xml", b"")
        assert response.status_code == 400

    def test_unparseable_file_rejected(self, client):
        response = upload(client, "security.xml", b"this is not an event log")
        assert response.status_code == 400

    def test_imported_events_drive_detection(self, client):
        declaration = '<?xml version="1.0" encoding="utf-8"?>'
        body_xml = "".join(
            make_xml(
                event_id=4625,
                account="svc_backup",
                system_time=f"2026-10-24T10:0{index}:00.000000Z",
            ).replace(declaration, "")
            for index in range(5)
        )
        wrapped = f"<Events>{body_xml}</Events>"
        body = upload(client, "security.xml", wrapped.encode("utf-8")).json()
        assert body["imported"] == 5

        result = client.post("/api/detection/run").json()
        assert result["alerts_created"] >= 1

        alerts = client.get("/api/alerts").json()["alerts"]
        assert any(alert["rule_id"] == "sigma-win-4625-bruteforce" for alert in alerts)


class TestIncidentEnrichment:
    def test_incident_exposes_graph_and_chain(self, seeded_client):
        from conftest import make_event

        client, seed = seeded_client
        seed(
            [
                make_event(4625, account="svc_backup", timestamp="2026-10-24T10:00:00+00:00"),
                make_event(4625, account="svc_backup", timestamp="2026-10-24T10:01:00+00:00"),
                make_event(4625, account="svc_backup", timestamp="2026-10-24T10:02:00+00:00"),
                make_event(4625, account="svc_backup", timestamp="2026-10-24T10:03:00+00:00"),
                make_event(4625, account="svc_backup", timestamp="2026-10-24T10:04:00+00:00"),
                make_event(4624, account="svc_backup", timestamp="2026-10-24T10:05:00+00:00"),
            ]
        )
        client.post("/api/detection/run")
        created = client.post("/api/incidents/correlate").json()
        assert created["incidents_created"] >= 1

        incident = client.get("/api/incidents").json()["incidents"][0]
        assert "entities" in incident
        assert "attack_chain" in incident
        assert incident["chain_score"] >= 0
        assert incident["entity_graph"]["nodes"]

        detail = client.get(f"/api/incidents/{incident['id']}").json()
        assert detail["entities"]
        assert detail["attack_chain"]["covered_count"] >= 1

    def test_rebuild_replaces_existing_incidents(self, seeded_client):
        from conftest import make_event

        client, seed = seeded_client
        seed(
            [
                make_event(4625, account="svc_backup",
                           timestamp=f"2026-10-24T10:0{index}:00+00:00")
                for index in range(5)
            ]
            + [make_event(4624, account="svc_backup", timestamp="2026-10-24T10:06:00+00:00")]
        )
        client.post("/api/detection/run")
        first = client.post("/api/incidents/correlate").json()
        assert first["total_incidents"] >= 1

        rebuilt = client.post("/api/incidents/correlate", params={"rebuild": True}).json()
        assert rebuilt["incidents_removed"] == first["total_incidents"]
        assert rebuilt["total_incidents"] == rebuilt["incidents_created"]
        assert "Rebuilt from scratch" in rebuilt["message"]

    def test_correlation_window_is_configurable(self, seeded_client):
        from conftest import make_event

        client, seed = seeded_client
        seed([make_event(4625, timestamp="2026-10-24T10:00:00+00:00")])
        client.post("/api/detection/run")
        body = client.post("/api/incidents/correlate", params={"window_minutes": 5}).json()
        assert body["window_minutes"] == 5


class TestEntityEndpoint:
    def test_entities_are_listed(self, seeded_client):
        from conftest import make_event

        client, seed = seeded_client
        seed(
            [
                make_event(4625, account="a.kim",
                           timestamp=f"2026-10-24T10:0{index}:00+00:00")
                for index in range(5)
            ]
        )
        client.post("/api/detection/run")

        body = client.get("/api/entities").json()
        assert body["total_entities"] >= 1
        assert any(entity["key"] == "user:a.kim" for entity in body["entities"])
