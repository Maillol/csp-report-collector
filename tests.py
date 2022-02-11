#!/usr/bin/env python3

import csp_report_collector
import json
import mongomock
from unittest.mock import patch
from bson.objectid import ObjectId

client = csp_report_collector.app.test_client()
mongo = mongomock.MongoClient()


class TestErrorResponses():
    def test_400_error(self):
        r = client.post('/')
        assert r.status_code == 400

    def test_404_error(self):
        r = client.get('/404')
        assert r.status_code == 404

    def test_405_error(self):
        r = client.trace('/')
        assert r.status_code == 405


class TestRoutesIndexGet():
    def test_get_index(self):
        r = client.get('/')
        assert r.status_code == 200
        assert r.data.decode('UTF-8') == 'OK'


@patch.object(csp_report_collector, "mongo", mongo)
class TestRoutesIndexPost():
    document_uri = "https://example.com/foo/bar"
    violated_directive = "default-src self"
    blocked_uri = "http://evilhackerscripts.com"

    data = {
        "csp-report": {
            "document-uri": document_uri,
            "violated-directive": violated_directive,
            "blocked-uri": blocked_uri,
        }
    }

    def test_fail_when_content_type_is_not_application_csp_report(self):
        r = client.post('/', content_type='text/html')

        assert r.status_code == 400

    def test_fail_on_empty_post_data(self):
        r = client.post('/', content_type='application/csp-report')

        assert r.status_code == 400
        assert r.headers['Content-Type'] == 'application/json'

    def test_csp_report_stored_in_mongo(self):
        r = client.post('/', content_type='application/csp-report', data=json.dumps(self.data))

        db_cursor = mongo['csp_reports']['example.com'].find({})
        db_entry = db_cursor[0]

        assert r.status_code == 204
        assert db_entry['document_uri'] == self.document_uri
        assert db_entry['violated_directive'] == self.violated_directive.split(' ', 1)[0]
        assert db_entry['blocked_uri'] == self.blocked_uri

    def test_log_output_with_x_real_ip(self, capsys):
        headers = {}
        headers['x-real-ip'] = '127.0.0.2'

        r = client.post('/', content_type='application/csp-report', headers=headers, data=json.dumps(self.data))
        out, err = capsys.readouterr()

        for line in out.splitlines():
            if '127.0.0.1 127.0.0.2 ' in line:
                break

        assert r.status_code == 204
        assert line.endswith(f'127.0.0.1 127.0.0.2 application/csp-report {{\'document-uri\': \'{self.document_uri}\', \'violated-directive\': \'{self.violated_directive}\', \'blocked-uri\': \'{self.blocked_uri}\'}}')

    def test_log_output_with_x_forwarded_for(self, capsys):
        headers = {}
        headers['x-forwarded-for'] = '127.0.0.3'

        r = client.post('/', content_type='application/csp-report', headers=headers, data=json.dumps(self.data))
        out, err = capsys.readouterr()

        for line in out.splitlines():
            if '127.0.0.1 127.0.0.3 ' in line:
                break

        assert r.status_code == 204
        assert line.endswith(f'127.0.0.1 127.0.0.3 application/csp-report {{\'document-uri\': \'{self.document_uri}\', \'violated-directive\': \'{self.violated_directive}\', \'blocked-uri\': \'{self.blocked_uri}\'}}')

    def test_log_output_default(self, capsys):
        r = client.post('/', content_type='application/csp-report', data=json.dumps(self.data))
        out, err = capsys.readouterr()

        for line in out.splitlines():
            if '127.0.0.1 - ' in line:
                break

        assert r.status_code == 204
        assert line.endswith(f'127.0.0.1 - application/csp-report {{\'document-uri\': \'{self.document_uri}\', \'violated-directive\': \'{self.violated_directive}\', \'blocked-uri\': \'{self.blocked_uri}\'}}')

    def test_blocked_uri_about(self):
        data = self.data
        data['csp-report']['blocked-uri'] = 'about'

        r = client.post('/', content_type='application/csp-report', data=json.dumps(data))

        assert r.status_code == 204

    def test_violated_directive_eval(self, capsys):
        data = self.data
        data['csp-report']['blocked-uri'] = ""
        data['csp-report']['violated-directive'] = 'script-src'

        r = client.post('/', content_type='application/csp-report', data=json.dumps(data))
        out, err = capsys.readouterr()

        ## The following line takes the 24 char hex representation of the ObjectId
        ## and reconstructs it so we can find by it.
        ## https://pymongo.readthedocs.io/en/latest/api/bson/objectid.html#bson.objectid.ObjectId
        for line in out.splitlines():
            if '_id' in line:
                j = json.loads(line)
                document_id = ObjectId(j['_id'])
                break

        db_entry = mongo['csp_reports']['example.com'].find_one({'_id': document_id})

        assert r.status_code == 204
        assert db_entry['blocked_uri'] == 'eval'

    def test_violated_directive_inline(self, capsys):
        data = self.data
        data['csp-report']['blocked-uri'] = ""
        data['csp-report']['violated-directive'] = 'style-src'

        r = client.post('/', content_type='application/csp-report', data=json.dumps(data))
        out, err = capsys.readouterr()

        ## The following line takes the 24 char hex representation of the ObjectId
        ## and reconstructs it so we can find by it.
        ## https://pymongo.readthedocs.io/en/latest/api/bson/objectid.html#bson.objectid.ObjectId
        for line in out.splitlines():
            if '_id' in line:
                j = json.loads(line)
                document_id = ObjectId(j['_id'])
                break

        db_entry = mongo['csp_reports']['example.com'].find_one({'_id': document_id})

        assert r.status_code == 204
        assert db_entry['blocked_uri'] == 'inline'
