#!/usr/bin/env python3
__version__ = "0.4.0a"

## Standard library imports
from urllib.parse import urlparse
from datetime import datetime
from os import getenv, path
import html
import json
import logging
import sys

## Third party library imports
from configparser import ConfigParser, NoOptionError
from flask import Flask, jsonify, abort, make_response, request
from pymongo import MongoClient

## Debug
# from pdb import set_trace as st

mongo_host = getenv("CSP_MONGO_HOST", "localhost")
mongo_port = getenv("CSP_MONGO_PORT", 27017)
mongo_user = getenv("CSP_MONGO_USER", None)
mongo_pass = getenv("CSP_MONGO_PASS", None)
mongo_database = getenv("CSP_MONGO_DATABASE", "csp_reports")
mongo_connection_string = getenv("CSP_MONGO_CONNECTION_STRING", f"mongodb://{mongo_host}:{mongo_port}/{mongo_database}",)

app = Flask(__name__)
client = MongoClient(mongo_connection_string, username=mongo_user, password=mongo_pass, serverSelectionTimeoutMS=1000)
logger = logging.getLogger(__name__)


REPORT_API_PATH = getenv("REPORT_API_PATH", "/")


def read_conf(conf_path) -> dict:
    """
    Read CASSH configuration file and return metadata.
    """

    if not path.isfile(conf_path):
        logger.error("Can't read configuration file... ({})".format(conf_path))
        exit(1)

    config = ConfigParser()
    config.read(conf_path)
    options = dict()

    options["mongodb"] = dict()
    if not config.has_option("mongodb", "enable"):
        options["mongodb"]["enable"] = False
    else:
        options["mongodb"]["enable"] = config.get("mongodb", "enable") == "True"
    try:
        options["mongodb"]["port"] = int(config.get("mongodb", "port"))
        options["mongodb"]["host"] = config.get("mongodb", "host")
        options["mongodb"]["user"] = config.get("mongodb", "user")
        if options["mongodb"]["user"] == "None":
            options["mongodb"]["user"] = None
        options["mongodb"]["pass"] = config.get("mongodb", "pass")
        if options["mongodb"]["pass"] == "None":
            options["mongodb"]["pass"] = None
        options["mongodb"]["database"] = config.get("mongodb", "database")
    except (NoOptionError, ValueError) as error_msg:
        logger.error("Can't read configuration file... ({})".format(error_msg))
        exit(1)

    return options


@app.errorhandler(400)  # 400 Bad Request
def error_400(error):
    return make_response(jsonify({"error": str(error)}), 400)


@app.errorhandler(404)  # 404 Not Found
def error_404(error):
    return make_response(jsonify({"error": str(error)}), 404)


@app.errorhandler(405)  # 405 Method Not Allowed
def error_405(error):
    return make_response(jsonify({"error": str(error)}), 405)


## POST /
@app.route(path.join(REPORT_API_PATH, "/"), methods=["POST"])
def csp_receiver():
    logger = logging.getLogger(__name__)

    ## https://junxiandoc.readthedocs.io/en/latest/docs/flask/flask_request_response.html
    if request.content_type != "application/csp-report":
        abort(400)

    if not request.data:
        abort(400, "JSON data was not provided")

    csp_report = json.loads(request.data.decode("UTF-8"))["csp-report"]

    if "X-Real-IP" in request.headers:
        x_real_ip = request.headers["X-Real-IP"]
        logger.info(f"{datetime.now()} {request.remote_addr} {x_real_ip} {request.content_type} {csp_report}")
    elif "X-Forwarded-For" in request.headers:
        x_forwarded_for = request.headers["X-Forwarded-For"]
        logger.info(f"{datetime.now()} {request.remote_addr} {x_forwarded_for} {request.content_type} {csp_report}")
    else:
        logger.info(f"{datetime.now()} {request.remote_addr} - {request.content_type} {csp_report}")

    blocked_uri = html.escape(csp_report["blocked-uri"], quote=True)
    document_uri = html.escape(csp_report["document-uri"], quote=True)
    violated_directive = html.escape(csp_report["violated-directive"], quote=True).split(" ", 1)[0]

    if blocked_uri == "about" or document_uri == "about":
        return make_response("", 204)

    elif not blocked_uri:
        if violated_directive == "script-src":
            blocked_uri = "eval"

        elif violated_directive == "style-src":
            blocked_uri = "inline"

    if OPTIONS["mongodb"]["enable"] or True:
        domain = urlparse(document_uri).hostname
        collection = client[mongo_database][domain]
        post = {
            "document_uri": document_uri,
            "blocked_uri": blocked_uri,
            "violated_directive": violated_directive,
        }

        document = collection.find_one(post)

        if document:
            document_id = document["_id"]
            # print(f"Update doc: {document_id}")
        else:
            document_id = collection.insert_one(post).inserted_id
            # print(f"New doc: {document_id}")

        collection.update_one(
            {"_id": document_id}, {"$set": {"last_updated": datetime.now()}, "$inc": {"count": 1}},
        )

        if "py.test" in sys.modules:
            print(f'{{"_id": "{document_id}"}}')

    return make_response(jsonify(None), 204)


## GET /health
@app.route(path.join(REPORT_API_PATH, "/health"))
def get_health():
    response = {"status": "OK"}
    return make_response(jsonify(response))


## GET /version
@app.route(path.join(REPORT_API_PATH, "/version"))
def get_version():
    response = {"name": __name__, "version": __version__}
    return make_response(jsonify(response))


OPTIONS = read_conf("settings.conf")
MONGO_CONNECTION_STRING = "mongodb://{}:{}".format(OPTIONS["mongodb"]["host"], OPTIONS["mongodb"]["port"])
CLIENT = MongoClient(MONGO_CONNECTION_STRING, username=OPTIONS["mongodb"]["user"], password=OPTIONS["mongodb"]["pass"],)
DB = CLIENT[OPTIONS["mongodb"]["database"]]


if __name__ == "__main__":
    app.run(host="0.0.0.0")
