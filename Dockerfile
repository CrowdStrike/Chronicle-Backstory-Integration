FROM python:3.7-slim
MAINTAINER CrowdStrke Community
ARG APP_USER=backstory
RUN useradd --no-log-init -r ${APP_USER}
COPY EventStreams/ /
RUN python3 setup.py install
CMD [ "chronicle-client" ]
