# AES

Python implementation of AES encryption algorithm. 

Code is divided into three files:
 - `aes.py` contains all the parts of AES algorithm: constants, transformations, key expansion algorithm, ciphering and deciphering algorithms. There are also some helper functions along with more user-friendly encryption and decryption API.
 - `main.py` demonstrates use of API by letting user to encrypt his own keyboard input and decrypt the result to get original message.
 - `tests.py`contains unit tests for helper functions, key expansion algorithm and ciphering-deciphering algorithms.

The implementation is based on NumPy package for convenient multi-dimensional array usage.

Benchmarking has shown that encryption of 1 MB of data takes 29.60783100128174 s on Intel Core i7-6700HQ CPU. This result is not bad but also not especially great. 
Performance bottleneck is mainly caused by `mix_columns` function which takes 50% of the computation time and requires very careful low-level optimization techniques to achieve high speed. Current implementation is already quite optimized (more than 4x time reduction compared to first version) by appropriately using NumPy paralellization abilities and lookup tables. 
One of the most promising possible optimization is support for GPU utilization.
