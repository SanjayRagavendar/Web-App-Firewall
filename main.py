import argparse
from flask_app.modules.checker import add_block
from flask_app.modules.checker import del_block
from flask_app.modules.print_log import print_log
from flask_app.modules.checker import req_limit_sec
from flask_app.modules.checker import req_limit_min


parser = argparse.ArgumentParser()

# Adding the arguments with appropriate types and help messages
parser.add_argument('-b', '--block', type=str, help='IP Address to block')
parser.add_argument('-u', '--unblock', type=str, help='Unblock a blocked IP')
parser.add_argument('-l', '--show_log', type=int, help='Display the latest log')
parser.add_argument('-r', '--requests_per_sec', type=int, help='Enter the number of requests per second')
parser.add_argument('-m','--requests_per_min',type=int,help='Enter the number of requests per minute')

args = parser.parse_args()

if args.block:
    add_block(args.block)

if args.unblock:
    del_block(args.unblock)

if args.show_log:
    print_log(args.show_log)

if args.requests_per_sec:
    req_limit_sec(args.requests_per_sec)

if args.requests_per_min:
    req_limit_min(args.requests_per_min)