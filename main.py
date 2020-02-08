import sys
import requests
import argparse
import time
import pathlib
from hashlib import sha1

PASSWORDSAPI = "https://api.pwnedpasswords.com/range/"


def compare_hashes(database, tail):
    if tail in database.keys():
        return database[tail]
    else:
        return None


def get_api_response(first5_chars):
    url = PASSWORDSAPI + first5_chars
    res = requests.get(url)
    if res.status_code != 200:
        sys.exit("Something is wrong. The API might be down. Try again later")
    response = {}
    for line in res.text.splitlines():
        tail, count = line.split(':')
        response[tail] = count
    return response


def hash_password(password):
    enc_password = sha1(password.encode('utf-8')).hexdigest().upper()
    return enc_password


def check_passwords(passwords):
    start_time = time.time()
    for password in passwords:
        # print(time.time()-start_time)
        enc_password = hash_password(password)
        first5, tail = enc_password[:5], enc_password[5:]
        response = get_api_response(first5)
        pwned_count = compare_hashes(response, tail)
        if pwned_count:
            print(f'Oh no! {password} has been pwned {pwned_count} times!')
        else:
            print(f"Nice! {password} hasn't been pwned and is probably safe")
        time.sleep(1.5)


def get_args():
    parser = argparse.ArgumentParser(description='Check if your password has been pwned')
    parser.add_argument('password', nargs='*', help='Password to check in database. Multiple passwords are allowed.')
    parser.add_argument('-f', '--file', nargs='?', type=pathlib.Path, help="File name to read passwords from")
    args = parser.parse_args()
    if not (args.password or args.file):
        raise argparse.ArgumentTypeError("You must either enter one or more passwords to check or supply a file path")
    return args


def main():
    args = get_args()
    file_path = args.file
    if args.password:
        passwords = args.password
    else:
        passwords = []
    if file_path:
        with open(file_path, 'r') as file:
            passwords.extend(file.read().splitlines())
    check_passwords(passwords)


if __name__ == '__main__':
    main()
