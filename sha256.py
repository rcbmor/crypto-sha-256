__author__ = 'ricardo.moreira@acad.pucrs.br'

import os

from Crypto.Hash import SHA256
"""
>>> from Crypto.Hash import SHA256
>>>
>>> h = SHA256.new()
>>> h.update(b'Hello')
>>> print h.hexdigest()
"""

BLOCK_SIZE = 1024


def sha256_buffer(buff):
    """
    Calculates sha256 of buffer

    :param buff: the input buffer
    :return: sha 256 hexdigest
    """
    h = SHA256.new()
    h.update(buff)
    return h.digest()


def process_chunk(input_file, pos, prev_hash256, chunk_size):
    """
    Process each chunk from input_file at pos position
        SHA_256 ( chunk | hash256_previous_chunk )

    :param input_file: the file being processed
    :param pos: the position of the chunk
    :param chunk_size: the size of the chunk to process
    :param prev_hash256: the previous chunk SHA256

    :return: tuple(chunk, h256)
        chunk: current chunk processed
        h256: SHA-256 value for current chunk
    """
    input_file.seek(pos)
    chunk = input_file.read(chunk_size)
    chunk = chunk + prev_hash256
    chunk_len = len(chunk)
    h256 = sha256_buffer(chunk)
    return chunk, h256


def calculate_sha256(input_file, length, chunk_size=BLOCK_SIZE):
    """
    Process chunks in reverse order to calculate sha-256

    :param input_file: the input file
    :param length: the input file length
    :param chunk_size: the size of the chunk
    :return: hex encoded sha256 hash
    """

    h256 = ''
    pos = 0

    # process in reverse order each chunk
    for pos in range(length - chunk_size, 0, -chunk_size):
        chunk, h256 = process_chunk(input_file, pos, h256, chunk_size)

    # process last chunk reminder
    if pos > 0:
        chunk, h256 = process_chunk(input_file, 0, h256, pos)

    return h256


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Calculates SHA-256-H0 of a file.')
    parser.add_argument('file', help="input filename", metavar='FILE')
    parser.add_argument('-sha256', help="SHA-256-H0 expected value", metavar='SHA-256')
    args = parser.parse_args()

    filename = args.file
    try:
        file_length = os.path.getsize(filename)
        with open(filename, mode='rb', buffering=BLOCK_SIZE) as input_file:
            sha256 = calculate_sha256(input_file, file_length)

        if args.sha256:
            print("SHA-256", args.sha256 == sha256.encode("hex"), args.sha256, sha256.encode("hex"))

    except IOError:
        print("file not found: {}".format(filename))
    except Exception as e:
        print("unknown error while attempting to read file length: %s", e)
