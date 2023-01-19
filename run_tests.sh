#!/usr/bin/env bash
# run_tests.sh

clear

if [[ "$1" == "c"  ]]; then
    coverage run -m pytest -s tests/ && coverage report
else
    pytest -s tests/
fi
