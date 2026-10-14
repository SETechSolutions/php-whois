#!/usr/bin/env sh

composer install

# Live tests query real servers, so they only run when asked for: /run-tests.sh --group live
case "$*" in
    *--group*) EXCLUDE="" ;;
    *) EXCLUDE="--exclude-group live" ;;
esac

php vendor/bin/phpunit --bootstrap tests/bootstrap.php $EXCLUDE tests $@
