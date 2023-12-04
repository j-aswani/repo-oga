FROM python:3.10-slim-buster as base

FROM base as pip

COPY ./service/src/requirements.txt /tmp/requirements.txt
RUN pip install --upgrade pip setuptools && \
    pip install -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

FROM base

ENV NAME=telcorouter \
    USERNAME=aggregator \
    USERID=12351
ENV WORKDIRECTORY=/opt/${USERNAME}/${NAME} \
    CONFIGDIRECTORY=/etc/${NAME} \
    LOGDIRECTORY=/var/log/${NAME}

RUN apt-get update && \
    # Upgrade dependencies
    apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/*

COPY ./service/src ${WORKDIRECTORY}
COPY ./docker-entrypoint.sh ${WORKDIRECTORY}/bin/docker-entrypoint.sh
COPY --from=pip /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY --from=pip /usr/local/bin /usr/local/bin

RUN groupadd -g ${USERID} ${USERNAME} && \
    useradd -u ${USERID} -g ${USERID} -ms /bin/bash ${USERNAME} && \
    mkdir -p ${LOGDIRECTORY} ${CONFIGDIRECTORY} ${WORKDIRECTORY}/aggregator/logs && \
    chown -R ${USERNAME}:${USERNAME} ${WORKDIRECTORY} \
    ${CONFIGDIRECTORY} \
    ${LOGDIRECTORY}

VOLUME ${LOGDIRECTORY} \
       ${CONFIGDIRECTORY}

WORKDIR ${WORKDIRECTORY}
CMD ["./bin/docker-entrypoint.sh"]
EXPOSE 9000
