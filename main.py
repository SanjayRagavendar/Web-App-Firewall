import argparse
import pyshark
from modules.add_block import add_block
from modules.del_block import del_block
from modules.del_block import block_check
from modules.print_log import print_log
from modules.rate_limit import limit_no
from modules.rate_limit import rate_limit
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

def main():
    capture = pyshark.LiveCapture(interface='wlan0')

    for packet in capture.sniff_continuously():
        process_packet(packet)

if __name__ == '__main__':
    main() 