
# Stream ciphers
  
Python implementation of stream cipher algorithms.  

Implemented ciphers:
 - RC4 (`rc4.py`)
 - Salsa20 (`salsa20.py`)
 - AES-ECB (`aes_ecb.py`)
 - AES-CBC (`aes_cbc.py`)
 - AES-CFB (`aes_cfb.py`)
 - AES-OFB (`aes_ofb.py`)
 - AES-CTR (`aec_ctr.py`)
  
Other code files:
- `aes.py` implements AES block cipher, used by different modes of operatoin
- `helpers.py` contains common utility functions that are used in several ciphers
-  `benchmark.py` measures execution time of all implemented algorithms
-  `tests.py`contains unit tests adopted from specifications
    

## Benchmarking results
Encryption of 100 KB:

| RC4     | Salsa20 | AES-ECB | AES-CBC | AES-OFB | AES-CTR | AES-CFB (s=8 bits) | AES-CFB  (s=32 bits) | AES-CFB  (s=64 bits) |
|---------|---------|---------|---------|---------|---------|--------------------|----------------------|----------------------|
| 0.355 s | 3.440 s | 3.001 s | 2.959 s | 3.075 s | 3.121 s | 48.847 s           | 11.652 s             | 5.799 s              |

