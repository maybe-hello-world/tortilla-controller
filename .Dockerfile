FROM python:3
LABEL maintainer="maybe.hello.world@gmail.com"

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir gunicorn
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./
COPY connectors ./

EXPOSE 5876

CMD ["gunicorn",  "-b", "0.0.0.0:5876", "app:app"]