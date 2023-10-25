from __future__ import print_function
import base64
import json
import os.path
import pprint
import sys
import time
import zlib

# Terminal colors
class bcolors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def pad_base64(data):
    """Makes sure base64 data is padded
    """
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += '='* (4 - missing_padding)
    return data


def decompress_partial(data):
    """Decompress arbitrary deflated data. Works even if header and footer is missing
    """
    decompressor = zlib.decompressobj()
    return decompressor.decompress(data)


def decompress(JWT):
    """Split a JWT to its constituent parts.
    Decodes base64, decompress if required. Returns but does not validate the signature.
    """
    header, jwt, signature = JWT.split('.')

    printable_header = base64.urlsafe_b64decode(pad_base64(header)).decode('utf-8')

    if json.loads(printable_header).get("zip", "").upper() == "DEF":
        printable_jwt = decompress_partial(base64.urlsafe_b64decode(pad_base64(jwt)))
    else:
        printable_jwt = base64.urlsafe_b64decode(pad_base64(jwt)).decode('utf-8')

    printable_signature = base64.urlsafe_b64decode(pad_base64(signature))

    return json.loads(printable_header), json.loads(printable_jwt), printable_signature


def showJWT(JWT):
    header, jwt, signature = decompress(JWT)

    # Printing JWT Header
    print(bcolors.RED + "Header:  " + bcolors.ENDC, end="")
    json_formatted_header = json.dumps(header, indent=4)
    print(bcolors.RED + json_formatted_header + bcolors.ENDC)

    # Printing JWT Token
    print(bcolors.GREEN + "Token:   " + bcolors.ENDC, end="")
    json_formatted_token = json.dumps(jwt, indent=4)
    print(bcolors.GREEN + json_formatted_token + bcolors.ENDC)

    # Printing other info
    print(bcolors.YELLOW + "Issued at:  {} (localtime)".format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(jwt['iat'])) if 'iat' in jwt else 'Undefined' + bcolors.ENDC))
    print(bcolors.YELLOW + "Not before: {} (localtime)".format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(jwt['nbf'])) if 'nbf' in jwt else 'Undefined' + bcolors.ENDC))
    print(bcolors.YELLOW + "Expiration: {} (localtime)".format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(jwt['exp'])) if 'exp' in jwt else 'Undefined' + bcolors.ENDC))

def print_header():
    print()
    print("+----------------------------------------+")
    print("|              JWT DECODER               |")
    print("+----------------------------------------+")
    print()
    print()

if __name__ == "__main__":

    print_header()

    if len(sys.argv) > 1:
        jwt = sys.argv[1]

        if os.path.exists(jwt):
            with open(sys.argv[1], "r") as input_file:
                jwt = input_file.read().strip()

        showJWT(jwt)
