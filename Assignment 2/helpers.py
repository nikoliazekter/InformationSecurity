import itertools

import numpy as np


def hex_to_stream(hex_string):
    return (np.uint8(int(hex_string[i:i + 2], 16)) for i in range(0, len(hex_string), 2))


def stream_to_hex(stream):
    return ''.join(hex(byte)[2:].zfill(2) for byte in stream)


def stream_to_blocks(stream, n, padding=False):
    stream = iter(stream)
    while True:
        new_block = list(itertools.islice(stream, n))
        if len(new_block) < n:
            if padding:
                new_block = pad(new_block, n)
                yield new_block
            return
        yield new_block


def blocks_to_stream(blocks, padding=False):
    if not padding:
        return list(itertools.chain(*blocks))

    stream = []
    last_block = []
    for block in blocks:
        stream += last_block
        last_block = block
    stream += unpad(last_block)
    return stream


def pad(block, n):
    padding_len = n - len(block)
    return block + [padding_len] * padding_len


def unpad(block):
    padding_len = block[-1]
    return block[:len(block) - padding_len]


def xor_bytes(bytes1, bytes2):
    assert (len(bytes1) == len(bytes2))
    return [bytes1[i] ^ bytes2[i] for i in range(len(bytes1))]
