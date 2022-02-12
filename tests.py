#!/usr/bin/env python3

import csp_report_collector
import json
import mongomock
from unittest.mock import patch
from bson.objectid import ObjectId
from urllib.parse import urlparse

mongo_client = mongomock.MongoClient()
test_client = csp_report_collector.app.test_client()


class TestErrorHandlers:
    def test_400_error(self):
        r = test_client.post("/")

        assert r.status_code == 400
        assert r.headers["Content-Type"] == "application/json"
        assert r.data.decode("UTF-8") == '{"error":"400 Bad Request: The browser (or proxy) sent a request that this server could not understand."}\n'

    def test_404_error(self):
        r = test_client.get("/404")

        assert r.status_code == 404
        assert r.headers["Content-Type"] == "application/json"
        assert r.data.decode("UTF-8") == '{"error":"404 Not Found: The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again."}\n'

    def test_405_error(self):
        r = test_client.trace("/")

        assert r.status_code == 405
        assert r.headers["Content-Type"] == "application/json"
        assert r.data.decode("UTF-8") == '{"error":"405 Method Not Allowed: The method is not allowed for the requested URL."}\n'


@patch.object(csp_report_collector, "client", mongo_client)
class TestEndpointIndex:
    def test_get_index(self):
        r = test_client.get("/")

        assert r.status_code == 405

    document_uri = "https://example.com/foo/bar"
    violated_directive = "default-src self"
    blocked_uri = "http://evilhackerscripts.com"
    hostname = urlparse(document_uri).hostname
    data = {"csp-report": {"document-uri": document_uri, "violated-directive": violated_directive, "blocked-uri": blocked_uri}}

    def test_fail_when_content_type_is_not_application_csp_report(self):
        r = test_client.post("/", content_type="text/html")

        assert r.status_code == 400
        assert r.headers["Content-Type"] == "application/json"

    def test_fail_on_empty_post_data(self):
        r = test_client.post("/", content_type="application/csp-report")

        assert r.status_code == 400
        assert r.headers["Content-Type"] == "application/json"
        assert r.data.decode("UTF-8") == '{"error":"400 Bad Request: JSON data was not provided"}\n'

    def test_success_response(self):
        r = test_client.post("/", content_type="application/csp-report", data=json.dumps(self.data))

        assert r.status_code == 204
        assert r.headers["Content-Type"] == "application/json"
        assert r.data.decode("UTF-8") == ""

    def test_csp_report_stored_in_mongo(self, capsys):
        r = test_client.post("/", content_type="application/csp-report", data=json.dumps(self.data))

        out, err = capsys.readouterr()
        document_id = json.loads(out)["_id"]
        db_cursor = mongo_client["csp_reports"][self.hostname].find({"_id": ObjectId(document_id)})
        db_entry = db_cursor[0]

        assert r.status_code == 204
        assert db_entry["document_uri"] == self.document_uri
        assert db_entry["violated_directive"] == self.violated_directive.split(" ", 1)[0]
        assert db_entry["blocked_uri"] == self.blocked_uri

    def test_log_output_with_x_real_ip(self, caplog):
        headers = {}
        headers["x-real-ip"] = "127.0.0.2"

        r = test_client.post("/", content_type="application/csp-report", headers=headers, data=json.dumps(self.data))

        assert r.status_code == 204

        for record in caplog.records:
            assert record.endswith(f"127.0.0.1 {headers['x-real-ip']} application/csp-report {{'document-uri': '{self.document_uri}', 'violated-directive': '{self.violated_directive}', 'blocked-uri': '{self.blocked_uri}'}}")

    def test_log_output_with_x_forwarded_for(self, caplog):
        headers = {}
        headers["x-forwarded-for"] = "127.0.0.3"

        r = test_client.post("/", content_type="application/csp-report", headers=headers, data=json.dumps(self.data),)

        assert r.status_code == 204

        for record in caplog.records:
            assert record.endswith(f"127.0.0.1 {headers['x-forwarded-for']} application/csp-report {{'document-uri': '{self.document_uri}', 'violated-directive': '{self.violated_directive}', 'blocked-uri': '{self.blocked_uri}'}}")

    def test_log_output_default(self, caplog):
        r = test_client.post("/", content_type="application/csp-report", data=json.dumps(self.data))

        assert r.status_code == 204

        for record in caplog.records:
            assert record.endswith(f"127.0.0.1 - application/csp-report {{'document-uri': '{self.document_uri}', 'violated-directive': '{self.violated_directive}', 'blocked-uri': '{self.blocked_uri}'}}")

    def test_blocked_uri_about(self):
        data = self.data
        data["csp-report"]["blocked-uri"] = "about"

        r = test_client.post("/", content_type="application/csp-report", data=json.dumps(data))

        assert r.status_code == 204

    def test_violated_directive_eval(self, capsys):
        data = self.data
        data["csp-report"]["blocked-uri"] = ""
        data["csp-report"]["violated-directive"] = "script-src"

        r = test_client.post("/", content_type="application/csp-report", data=json.dumps(data))
        out, err = capsys.readouterr()

        ## The following line takes the 24 char hex representation of the ObjectId
        ## and reconstructs it so we can find by it.
        ## https://pymongo.readthedocs.io/en/latest/api/bson/objectid.html#bson.objectid.ObjectId
        for line in out.splitlines():
            if "_id" in line:
                j = json.loads(line)
                document_id = ObjectId(j["_id"])
                break

        db_entry = mongo_client["csp_reports"][self.hostname].find_one({"_id": document_id})

        assert r.status_code == 204
        assert db_entry["blocked_uri"] == "eval"

    def test_violated_directive_inline(self, capsys):
        data = self.data
        data["csp-report"]["blocked-uri"] = ""
        data["csp-report"]["violated-directive"] = "style-src"

        r = test_client.post("/", content_type="application/csp-report", data=json.dumps(data))
        out, err = capsys.readouterr()

        ## The following line takes the 24 char hex representation of the ObjectId
        ## and reconstructs it so we can find by it.
        ## https://pymongo.readthedocs.io/en/latest/api/bson/objectid.html#bson.objectid.ObjectId
        for line in out.splitlines():
            if "_id" in line:
                j = json.loads(line)
                document_id = ObjectId(j["_id"])
                break

        db_entry = mongo_client["csp_reports"][self.hostname].find_one({"_id": document_id})

        assert r.status_code == 204
        assert db_entry["blocked_uri"] == "inline"


class TestEndpointHealth:
    def test_get_health(self):
        r = test_client.get("/health")

        assert r.status_code == 200
        assert r.headers["Content-Type"] == "application/json"
        assert r.data.decode("UTF-8") == '{"status":"OK"}\n'


class TestEndpointVersion:
    def test_get_version(self):
        r = test_client.get("/version")

        assert r.status_code == 200
        assert r.headers["Content-Type"] == "application/json"
        assert r.data.decode("UTF-8") == f'{{"name":"{csp_report_collector.__name__}","version":"{csp_report_collector.__version__}"}}\n'
