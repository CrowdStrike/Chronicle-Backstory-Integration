FROM python:3.7-slim
ARG APP_USER=appuser
RUN groupadd -r ${APP_USER} && useradd --no-log-init -r -g ${APP_USER} ${APP_USER}
ADD chronicleclient.py /
ADD offset.json /
RUN python3 -m pip install requests
CMD [ "python3", "./chronicleclient.py" ]