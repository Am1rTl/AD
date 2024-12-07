# syntax=docker/dockerfile:1-labs
FROM dunglas/frankenphp:1.3-php8.4
ARG DEBIAN_FRONTEND=noninteractive

RUN apt update -y && apt upgrade -y
RUN apt install libc6 libqt5core5a libqt5gui5 libqt5network5 \
                libqt5printsupport5 libqt5svg5 libqt5webkit5 \
                libqt5widgets5 libqt5xmlpatterns5 libstdc++6 \
                libpq-dev git unzip postgresql-client -y
RUN docker-php-ext-install pdo pdo_pgsql pgsql

ADD --checksum=sha256:9ee380d4d7b9a9848bd7497bbe03c91f65bd25ae4ad12b5466bed60a06029727 http://security.debian.org/debian-security/pool/updates/main/o/openssl/libssl1.1_1.1.1n-0+deb10u6_amd64.deb .
RUN dpkg -i libssl1.1_1.1.1n-0+deb10u6_amd64.deb && rm -f libssl1.1_1.1.1n-0+deb10u6_amd64.deb

ADD --checksum=sha256:d80831cdd8b826680d091f7d7eb50de4992c68a5c89935f1ba88d03013fa523c http://security.debian.org/debian-security/pool/updates/main/w/wkhtmltopdf/wkhtmltopdf_0.12.5-1+deb10u1_amd64.deb .
RUN dpkg -i wkhtmltopdf_0.12.5-1+deb10u1_amd64.deb && rm -f wkhtmltopdf_0.12.5-1+deb10u1_amd64.deb

COPY --from=composer:2.8.3 /usr/bin/composer /usr/local/bin/composer

WORKDIR /app
RUN echo "dsikfjuhna" > /app/key.txt
COPY --exclude=Dockerfile . .
RUN composer install

ENV PHPRC=/app/php.ini
EXPOSE 8080

CMD ["/bin/sh", "docker-entrypoint.sh"]
