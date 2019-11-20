FROM tiangolo/uvicorn-gunicorn-fastapi:python3.7-alpine3.8
LABEL maintainer="maybe.hello.world@gmail.com"

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

ENV MODULE_NAME="controller.main"
ENV PORT=5876
EXPOSE 5876

COPY . /app

