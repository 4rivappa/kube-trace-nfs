FROM ubuntu:22.04

RUN apt update && apt upgrade -y && apt-get install -y python3-pip

COPY setup-python.sh /
RUN chmod +x setup-python.sh
RUN /setup-python.sh

RUN ln -s /usr/bin/python3.8 /usr/bin/python

ENV MOUNT_PATH=/data

COPY generate_load.py /
ENTRYPOINT ["python3", "generate_load.py"]