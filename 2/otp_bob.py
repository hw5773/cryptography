import socket
import threading
import argparse
import logging
from etc import generate_c2i_mapper, generate_i2c_mapper

def decrypt(key, encrypted, i2c, c2i):
    decrypted = encrypted
    return decrypted

def handler(alice, key, i2c, c2i):
    encrypted = alice.recv(1024).decode()
    decrypted = decrypt(key, encrypted, i2c, c2i)
    logging.info("[*] Received: {}".format(decrypted))

    alice.close()

def run(addr, port, key, i2c, c2i):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))

    bob.listen(2)
    logging.info("[*] Bob is Listening on {}:{}".format(addr, port))

    while True:
        alice, info = bob.accept()

        logging.info("[*] Server accept the connection from {}:{}".format(info[0], info[1]))

        handle = threading.Thread(target=handler, args=(alice, key, i2c, c2i))
        handle.start()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-k", "--key", metavar="<otp key>", help="OTP key", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    i2c = generate_i2c_mapper()
    c2i = generate_c2i_mapper()

    run(args.addr, args.port, args.key, i2c, c2i)

if __name__ == "__main__":
    main()
