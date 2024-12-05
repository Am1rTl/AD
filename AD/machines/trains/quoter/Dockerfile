FROM theasp/clojurescript-nodejs:shadow-cljs-alpine as build-front


WORKDIR /frontend
# Get all deps of frontend
COPY package.json package-lock.json shadow-cljs.edn ./
RUN  npm install --save-dev shadow-cljs && shadow-cljs npm-deps

# Copy frontend files
COPY ./src/frontend ./src/frontend
COPY ./resources/public ./resources/public

RUN npx shadow-cljs release app && rm -fr ./node_modules

FROM clojure:temurin-19-tools-deps-bullseye-slim AS build-jar
# Install deps for backend
WORKDIR /src

COPY deps.edn build.clj .
RUN clj -P

RUN clj -T:build prep
# Add compiled frontend 
COPY . .
COPY --from=build-front /frontend/resources/public ./resources/public
# Build .jar
RUN clj -T:build ci

FROM openjdk:19-jdk-alpine
WORKDIR /app

# Rename `release.jar` to your uberjar name
COPY --from=build-jar /src/target/quoter-standalone.jar release.jar
CMD ["java", "-jar", "release.jar"]