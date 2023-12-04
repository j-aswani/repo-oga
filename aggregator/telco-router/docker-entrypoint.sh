#!/bin/bash

APPNAME=telcorouter
USER=aggregator
APPMODULE=aggregator.wsgi:application
DAEMON=gunicorn
BIND=0.0.0.0:${PORT}
[ -z "${WORKERS}" ] && WORKERS=2 || true
BASE_DIR="/opt/aggregator/telcorouter"

pushd ${BASE_DIR} && ${DAEMON} --bind=${BIND} --workers=${WORKERS} ${APPMODULE}
