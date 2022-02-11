FROM alpine:3

LABEL Author="Andy Dustin <andy.dustin@gmail.com>"
LABEL Version="0.4.0"

RUN apk add --update \
    python3 \
    python3-dev \
    py3-pip \
    gcc \
    musl-dev \
  && rm -rf /var/cache/apk/*

COPY . /app
COPY settings.conf.example settings.conf

RUN pip3 install -U pip
RUN pip3 install -r requirements.txt

EXPOSE 5000
WORKDIR /app
CMD [ "/usr/bin/gunicorn", "--workers=2", "--bind=0.0.0.0", "--name=csp-endpoint", "csp-report-collector:app" ]
