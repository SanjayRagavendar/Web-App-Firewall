import argparse
from modules.checker import add_block
from modules.checker import del_block
from modules.checker import block_check
from modules.print_log import print_log
from modules.checker import limit_no
from modules.checker import rate_limit
from modules.ml_check import ml_predict


parser = argparse.ArgumentParser()

# Adding the arguments with appropriate types and help messages
parser.add_argument('-b', '--block', type=str, help='IP Address to block')
parser.add_argument('-u', '--unblock', type=str, help='Unblock a blocked IP')
parser.add_argument('-l', '--show_log', type=int, help='Display the latest log')
parser.add_argument('-r', '--num_requests', type=int, help='Enter the number of requests per second')

args = parser.parse_args()

if args.block:
    add_block(args.block)

if args.unblock:
    del_block(args.unblock)

if args.show_log:
    print_log(args.show_log)

if args.num_requests:
    limit_no(args.num_requests)

def process_packet(p):
    try:
        block_check(p)
        rate_limit(p)
        ml_predict(p)

    except AttributeError:
        pass

def check(request):
    process_packet(request)