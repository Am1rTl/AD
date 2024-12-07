FROM node:22.11-bullseye-slim AS build-stage

WORKDIR /app
COPY frontend/package*.json ./
RUN npm install
COPY ./frontend/ .
RUN npm run build \
    && rm -fr ./node_modules

FROM nginx:1.21-alpine AS production-stage

WORKDIR /app
COPY --from=build-stage /app/dist ./

COPY ./docker/nginx.conf /etc/nginx/nginx.conf
