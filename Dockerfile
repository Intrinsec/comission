FROM python:3-alpine
LABEL description "CoMisSion - WhiteBox CMS analysis" version="0.1"

WORKDIR /opt/app/

COPY requirements.txt /opt/app/
RUN pip install -r requirements.txt
RUN rm requirements.txt

COPY utilsCMS.py /opt/app/
COPY comission.py /opt/app/


ENTRYPOINT ["/opt/app/comission.py"]
