#!/usr/bin/env bash
# run_tests.sh

clear

if [[ "$1" == "c"  ]]; then
    coverage run -m pytest -s src/tests/ && echo && coverage report && coverage html
else
    pytest -s src/tests/
fi
