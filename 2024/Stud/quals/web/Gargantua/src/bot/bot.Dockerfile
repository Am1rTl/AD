FROM node:22-alpine

RUN apk add chromium socat curl

WORKDIR /bot

COPY package.json package.json
RUN npm i

COPY bot.js bot.js
EXPOSE 3030

ARG FLAG="MCTF{example_flag}" # Provide real flag in args in docker-compose. This will act as a default value.
ENV FLAG=$FLAG

CMD ["socat", "TCP-LISTEN:3030,reuseaddr,fork", "SYSTEM:\"timeout -s SIGKILL 600 node /bot/bot.js\""]
