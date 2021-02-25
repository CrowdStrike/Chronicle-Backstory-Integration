FROM python:3.7-slim
ARG APP_USER=appuser
RUN groupadd -r ${APP_USER} && useradd --no-log-init -r -g ${APP_USER} ${APP_USER}
ADD src/chronicleclient.py /
ADD setup.py /
RUN python3 setup.py install
CMD [ "chronicle-client" ]


