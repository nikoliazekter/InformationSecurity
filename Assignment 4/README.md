# Public-key cryptosystems

Python implementation of textbook RSA and RSA-OAEP with Chinese remainder theorem decryption.
      
Code is divided into 6 files:    
- `sha256.py` implements SHA-256 hash function used by RSA-OAEP.
- `rsa.py` implements textbook RSA with Chinese remainder theorem decryption.
- `rsa_oaep.py` implements RSA-OAEP with Chinese remainder theorem decryption.
- `benchmark.py` contains code for measuring encryption and decryption times of both cryptosystems.
- `helpers.py` contains common utility functions and Miller-Rabin probabilistic primality test.
- `tests.py` contains tests for Miller-Rabin primality test and RSA/RSA-OAEP encryption-decryption.
    
## Benchmarking results   
  
N is bit length of prime numbers p and q.

M is bit length of plaintext.
  
| N    | M    | Keygen   | RSA enc    | RSA dec     | RSA-OAEP enc | RSA-OAEP dec |
|------|------|----------|------------|-------------|--------------|--------------|
| 384  | 240  | 0.2064 s | 0.001995 s | 0.0009973 s | 0.003989 s   | 0.002992 s   |
| 512  | 496  | 0.2453 s | 0.004987 s | 0.001995 s  | 0.006981 s   | 0.004987 s   |
| 1024 | 1520 | 9.4 s    | 0.0349 s   | 0.01293 s   | 0.0469 s     | 0.01596 s    |
| 1536 | 2544 | 56.38 s  | 0.09875 s  | 0.02792 s   | 0.1017 s     | 0.03391 s    |
