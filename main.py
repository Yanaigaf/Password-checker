import sys
import requests
import argparse
import time
from hashlib import sha1
PASSWORDSAPI = "https://api.pwnedpasswords.com/range/"


def compare_hashes(database, hashed_pass):
    tail = hashed_pass[5:]
    if tail in database.keys():
        return database[tail]


def get_api_response(enc_password):
    res_dict = {}
    url = PASSWORDSAPI + enc_password[:5]
    res = requests.get(url)
    if res.status_code != 200:
        sys.exit("Something is wrong. The API might be down. Try again later")
    res_list = res.text.split()
    for one_res in res_list:
        hex_pass, count = one_res.split(':')
        res_dict[hex_pass] = count
    return res_dict


def hash_password(password):
    enc_password = sha1(password.encode('utf-8')).hexdigest().upper()
    return enc_password

def get_args():
    parser = argparse.ArgumentParser(description='Check if your password has been pwned')
    parser.add_argument('password', nargs='*', help='Password to check in database. Multiple passwords are allowed.')
    parser.add_argument('-f', '--file', nargs='?', type=argparse.FileType('r'), help="File name to read passwords from")
    args = parser.parse_args()
    print(args.password, args.file)
    if not (args.password or args.file):
        raise argparse.ArgumentTypeError("You must either enter one or more passwords to check or supply a file path")
    return args


def main():
    args = get_args()
    passwords = args.password
    for password in passwords:
        enc_password = hash_password(password)
        response = get_api_response(enc_password)
        pwned_count = compare_hashes(response, enc_password)
        if pwned_count:
            print(f'Oh no! {password} has been pwned {pwned_count} times!')
        else:
            print(f"Nice! {password} hasn't been pwned and is probably safe")


if __name__ == '__main__':
    main()
