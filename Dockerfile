FROM python:3-alpine
LABEL description="CoMisSion - WhiteBox CMS analysis" version="0.1"

WORKDIR /opt/app/

COPY requirements.txt /opt/app/

RUN set -e; \
  apk add --no-cache --virtual build-deps \
    gcc \
    g++ \
    libc-dev \
    linux-headers \
  && apk add --no-cache libxslt-dev \
  && pip install -r requirements.txt \
  && apk del build-deps

RUN rm requirements.txt

COPY comission /opt/app/comission
COPY comission.py /opt/app/


ENTRYPOINT ["/opt/app/comission.py"]
