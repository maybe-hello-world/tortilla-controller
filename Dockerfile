FROM python:3.7-alpine
LABEL maintainer="maybe.hello.world@gmail.com"

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

RUN apk update && apk add py-gunicorn

COPY app.py ./
COPY config.py ./
COPY connectors ./connectors

EXPOSE 5876

CMD ["/usr/local/bin/gunicorn",  "-b", "0.0.0.0:5876", "app:app"]
