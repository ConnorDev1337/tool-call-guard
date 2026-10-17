# Throwaway image that runs AgentDojo for the scenario conversion only.
#
# The network is needed to build this image (pip install from the hashed lock);
# the conversion itself runs with `docker run --network none`. See README.md.

FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0

COPY requirements.lock /tmp/requirements.lock
RUN pip install --require-hashes --no-deps -r /tmp/requirements.lock \
    && useradd --create-home --uid 10001 converter

USER converter
WORKDIR /work
