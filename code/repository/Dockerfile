FROM ubuntu:latest

WORKDIR /app

COPY . /app

RUN apt update -y \
 && apt install -y python3-pip \
 && pip3 install cryptography==2.4.2

EXPOSE 8081

CMD ["python3", "main.py"]
