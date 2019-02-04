#!/usr/bin/env bash

php -q -f $(dirname $0)/validate-cli.php -- $@
ERR=$?

if [ $ERR -ne 0 ]; then
    echo -e "\nAn error occured."
    exit $ERR
else
    echo -e "\nSuccess.";
    exit 0
fi

