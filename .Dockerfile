FROM python:3
LABEL maintainer="maybe.hello.world@gmail.com"

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./
COPY connectors ./

CMD ["python", "./app.py"]