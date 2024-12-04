FROM archlinux:base-20241124.0.282387
RUN pacman -Syyu --noconfirm && pacman -S --noconfirm socat postgresql-libs libpqxx

WORKDIR /service
COPY --chmod=755 ./server.sh /
COPY ./[^scD]* .

ENTRYPOINT /server.sh
