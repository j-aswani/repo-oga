#!/bin/bash

APPNAME=baikal-authserver
USER=baikal
APPMODULE=authserver.wsgi:application
DAEMON=gunicorn
BIND=0.0.0.0:${PORT}
[ -z "${WORKERS}" ] && WORKERS=2 || true
BASE_DIR="/opt/baikal/baikal-authserver"

pushd ${BASE_DIR} && ${DAEMON} --bind=${BIND} --workers=${WORKERS} ${APPMODULE}
