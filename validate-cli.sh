#!/usr/bin/env bash

if [ -z $1 ]; then
    cat - | php -q -f $(dirname $0)/validate-cli.php
    ERR=$?
else
    php -q -f $(dirname $0)/validate-cli.php -- $1
    ERR=$?
fi

if [ $ERR -ne 0 ]; then
    echo -e "\nAn error occured."
    exit $ERR
else
    echo -e "\nSuccess.";
    exit 0
fi

