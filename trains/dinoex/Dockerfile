FROM ruby:3.3.0

WORKDIR /app
ADD . /app
RUN bundle install --system
RUN gem install rackup
ENV DISABLE_DATABASE_ENVIRONMENT_CHECK=1

EXPOSE 9292

ENTRYPOINT ["/bin/bash", "./docker-entrypoint.sh", "rackup", "--host", "0.0.0.0"]
