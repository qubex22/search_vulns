FROM ubuntu:latest

USER root
RUN mkdir /home/search_vulns&&chown ubuntu /home/search_vulns

RUN mkdir /home/data&&chown ubuntu /home/data

USER ubuntu

WORKDIR /home/search_vulns
USER root
RUN apt-get update >/dev/null && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y tzdata locales sudo git build-essential gcc >/dev/null
USER ubuntu
RUN git clone --quiet --depth 1 https://github.com/qubex22/search_vulns.git . 
USER root
RUN chown ubuntu install.sh
RUN chmod +x packages.sh
RUN ./packages.sh
USER ubuntu
RUN chmod +x install.sh
RUN ./install.sh
USER root
RUN rm -rf /var/lib/apt/lists/*
RUN sed -i -e "s/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/" /etc/locale.gen && \
    dpkg-reconfigure --frontend=noninteractive locales && \
    update-locale LANG=en_US.UTF-8
ENV LANG=en_US.UTF-8 LANGUAGE=en_US:en LC_ALL=en_US.UTF-8
USER ubuntu
ENTRYPOINT [ "./web_server.py" ]
