#!/bin/bash

# Parse results from Lox stat tests
echo 'Parse raw output to csv'

python3 raw_to_csv.py
python3 console_to_csv.py

#echo 'Make plots for data'
#python3 check_blockages.py
#python3 trust_promo_plot.py
#python3 make_tables.py

