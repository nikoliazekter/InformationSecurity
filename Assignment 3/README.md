
  
# Cryptographic hash functions 
  Python implementation of SHA-256 and Kupyna hash functions. 
    
Code is divided into four files:  
- `sha256.py` implements SHA-256 hash function
- `kupyna.py` implements Kupyna hash function  
- `proof_of_work.py` implements partial hash collision proof-of-work algorithm and measures respective hash functions' speeds
- `tests.py`contains unit tests adopted from specifications  
      
  
## Proof of work results 

Prefix is `'0102030405'`. 

N is the number of zero bits to match.

| N  | SHA-256    | Kupyna-256 | Kupyna-512 |
|----|------------|------------|------------|
| 2  | 0.002992 s | 0.004987 s | 0.05386 s  |
| 3  | 0.00399 s  | 0.006011 s | 0.08102 s  |
| 4  | 0.007874 s | 0.0489 s   | 0.8434 s   |
| 5  | 0.01695 s  | 0.1257 s   | 0.9639 s   |
| 6  | 0.01599 s  | 0.1621 s   | 1.001 s    |
| 7  | 0.01695 s  | 0.9032 s   | 1.149 s    |
| 8  | 0.09178 s  | 0.929 s    | 1.06 s     |
| 9  | 0.1147 s   | 3.336 s    | 1.243 s    |
| 10 | 0.3401 s   | 3.482 s    | 1.142 s    |
| 11 | 0.3261 s   | 8.531 s    | 1.882 s    |
| 12 | 2.043 s    | 21.76 s    | 84.81 s    |
| 13 | 2.55 s     | 26.54 s    | 493.1 s    |