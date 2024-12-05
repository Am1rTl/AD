FROM php:5.6-apache

WORKDIR /var/www/html
ADD app /var/www/html/

ARG FLAG
RUN mkdir -p /var/www/html/uploads && \
    chown -R www-data:www-data /var/www/html && \
    rm -rf flag* | echo $FLAG > flag_$(echo -n $FLAG | md5sum | awk '{print $1}') && \
    chmod 775 /var/www/html/uploads && \
    echo 'phar.readonly=0' >> /usr/local/etc/php/conf.d/docker-php-phar-readonly.ini &&\
    echo 'display_errors=0' >> /usr/local/etc/php/conf.d/docker-php-phar-readonly.ini &&\
    echo 'display_startup_errors=0' >> /usr/local/etc/php/conf.d/docker-php-phar-readonly.ini

