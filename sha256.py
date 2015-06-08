__author__ = 'ricardo.moreira@acad.pucrs.br'
"""
Cryptography exercise using SHA-256

The hex encoded h0 for the video file at http://www.pucrs.br/aeromovel/videos/video05.mp4 is:
8e423302209494d266a7ab7e1a58ca8502c9bfdaa31dfba70aa8805d20c087bd

To test:
$ python sha256.py -shah0 8e423302209494d266a7ab7e1a58ca8502c9bfdaa31dfba70aa8805d20c087bd video05.mp4

('8e423302209494d266a7ab7e1a58ca8502c9bfdaa31dfba70aa8805d20c087bd', '8e423302209494d266a7ab7e1a58ca8502c9bfdaa31dfba70aa8805d20c087bd', 'Valid')


"""
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
    h = SHA256.new(buff)
    return h.digest()


def process_chunk(input_file, pos, prev_hash256, chunk_size):
    """
    Process each chunk from input_file at pos position
        SHA_256 ( chunk | hash256_previous_chunk )

    :param input_file: the file being processed
    :param pos: the position of the chunk
    :param chunk_size: the size of the chunk to process
    :param prev_hash256: the previous chunk SHA256

    :return: SHA-256 value for current chunk
    """
    input_file.seek(pos)
    chunk = input_file.read(chunk_size)
    chunk = chunk + prev_hash256
    chunk_len = len(chunk)
    h256 = sha256_buffer(chunk)
    return h256


def calculate_sha256(input_file, length, chunk_size=BLOCK_SIZE):
    """
    Process chunks in reverse order to calculate sha-256

    :param input_file: the input file
    :param length: the input file length
    :param chunk_size: the size of the chunk
    :return: hex encoded sha256-H0 hash
    """

    h256 = ''

    # first the last block reminder
    reminder = length % chunk_size
    if reminder > 0:
        h256 = process_chunk(input_file, length-reminder, h256, reminder)

    # now, from second to last until the first
    # -1 to include 0
    # process in reverse order each chunk
    for pos in range(length-reminder-chunk_size, -1, -chunk_size):
        h256 = process_chunk(input_file, pos, h256, chunk_size)

    return h256


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Calculates SHA-256-H0 of a file.')
    parser.add_argument('file', help="input filename", metavar='FILE')
    parser.add_argument('-shah0', help="SHA-256-H0 expected value", metavar='SHA256-H0')
    args = parser.parse_args()

    filename = args.file
    try:
        file_length = os.path.getsize(filename)
        with open(filename, mode='rb') as input_file:
            sha256 = calculate_sha256(input_file, file_length)

        if args.shah0:
            print(args.shah0, sha256.encode("hex"), "Valid" if args.shah0 == sha256.encode("hex") else "Differ")

    except IOError:
        print("file not found: {}".format(filename))
    except Exception as e:
        print("unknown error while attempting to read file length: %s", e)
