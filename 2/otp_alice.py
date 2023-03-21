import socket
import argparse
import logging
from etc import generate_c2i_mapper, generate_i2c_mapper

def encrypt(key, msg, i2c, c2i):
    encrypted = msg
    return encrypted

def run(addr, port, msg, key, i2c, c2i):
    alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice.connect((addr, port))
    logging.info("[*] Client is connected to {}:{}".format(addr, port))
    logging.info("[*] Message: {}".format(msg))
    encrypted = encrypt(key, msg, i2c, c2i)
    alice.send(encrypted.encode())

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-m", "--message", metavar="<message to be sent>", help="Message to be sent", type=str, required=True)
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

    run(args.addr, args.port, args.message, args.key, i2c, c2i)
    
if __name__ == "__main__":
    main()
