from argparse import  ArgumentParser

def create_parser():
    parser = ArgumentParser(
        prog='python3 web_recon.py',
        description='A script to automatically do web recon, to speed up the initial recon process.',
    )

    parser.add_argument('url')
    parser.add_argument('-o',  '--output', help='output results to file')

    return parser.parse_args()

args = create_parser()

print(args.url)