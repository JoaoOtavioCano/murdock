FROM golang:1.26

ARG DB_USER
ARG DB_NAME
ARG DB_SSL_MODE
ARG DB_PASSWORD
ARG DB_HOST

ENV APP_HOME=/usr/src/app \
	PEPPER=pepper \
	JWT_SECRET=a-string-secret-at-least-256-bits-long \
	HOST=localhost \
	PORT=8080 \
	DB_USER=${DB_USER} \
	DB_PASSWORD=${DB_PASSWORD} \
	DB_NAME=${DB_NAME} \
	DB_SSL_MODE=${DB_SSL_MODE} \
	DB_HOST=${DB_HOST} \
	EMAIL_USERNAME=example@email.com \
	EMAIL_PASSWORD=password 

WORKDIR $APP_HOME

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && \
	go install github.com/pressly/goose/v3/cmd/goose@latest

COPY . .
RUN go build

EXPOSE ${PORT}

RUN echo "#!/bin/bash \n goose -dir ./migrations/ postgres \"user=${DB_USER} host=${DB_HOST} port=5432 password=${DB_PASSWORD} dbname=${DB_NAME} sslmode=${DB_SSL_MODE}\" up && ./murdock" > start.sh && chmod 766 start.sh

CMD [ "./start.sh" ]
