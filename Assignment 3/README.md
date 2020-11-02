
  
# Cryptographic hash functions 
  Python implementation of SHA-256 and Kupyna hash functions. 
    
Code is divided into four files:  
- `sha256.py` implements SHA-256 hash function
- `kupyna.py` implements Kupyna hash function  
- `proof_of_work.py` implements partial hash collision proof-of-work algorithm and measures respective hash functions' speeds
- `tests.py`contains unit tests adopted from specifications  
      
  
## Proof of work results 

Prefix is `'01020304050607080910'`. 

N is the number of zero bits to match.

| N | SHA-256     | Kupyna-256 | Kupyna-512 |  
|---|-------------|------------|------------|  
| 2 | 0.0 s       | 0.1536 s   | 0.4149 s   |  
| 3 | 0.0009894 s | 0.2563 s   | 0.4089 s   |  
| 4 | 0.001 s     | 0.6333 s   | 0.389 s    |  
| 5 | 0.008965 s  | 1.061 s    | 0.4548 s   |  
| 6 | 0.01096 s   | 0.9833 s   | 2.235 s    |  
| 7 | 0.1955 s    | 6.481 s    | 2.342 s    |  
| 8 | 0.2802 s    | 11.82 s    | 65.74 s    |  
| 9 | 0.3122 s    | 11.69 s    | 77.91 s    |