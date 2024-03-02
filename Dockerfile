FROM python:3.8-slim

ENV PYTHONUNBUFFERED 1
ENV SRC_DIR /tmp/src
ENV EXTENSION_DIR /opt/aurorastack
ENV PYTHONPATH "${PYTHONPATH}:/opt"

RUN apt-get update \
  && apt-get install -y wget build-essential

COPY pkg/pip_requirements.txt pip_requirements.txt
COPY templates/opt/aurorastack ${EXTENSION_DIR}

RUN pip install -r pip_requirements.txt
