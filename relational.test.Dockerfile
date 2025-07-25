# Use platform flag only on ARM64 (Apple Silicon)
ARG TARGETPLATFORM
FROM node:22.17.0-alpine

RUN apk add --no-cache bash curl
RUN npm i -g @nestjs/cli typescript ts-node

COPY package*.json /tmp/app/
RUN cd /tmp/app && npm install

COPY . /usr/src/app

COPY ./wait-for-it.sh /opt/wait-for-it.sh
RUN chmod +x /opt/wait-for-it.sh
COPY ./startup.relational.test.sh /opt/startup.relational.test.sh
RUN chmod +x /opt/startup.relational.test.sh
RUN sed -i 's/\r//g' /opt/wait-for-it.sh
RUN sed -i 's/\r//g' /opt/startup.relational.test.sh

WORKDIR /usr/src/app

RUN echo "" > .env

CMD ["/opt/startup.relational.test.sh"]
