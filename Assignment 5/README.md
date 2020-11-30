
# Elliptic curve digital signature
  
Python implementation of DSTU 4145-2002 elliptic curve digital signature algorithm.
        
Code is divided into 5 files:      
- `sha256.py` implements SHA-256 hash function.
- `galois_field.py` implements operations on polynomials over Galois field GF(2<sup>m</sup>).
- `elliptic_curve.py` implements operations on elliptic curves and their points over GF(2<sup>m</sup>).
- `signature.py` implements elliptic curve digital signature algorithm defined by DSTU 4145-2002.
- `tests.py` contains various tests to verify the correctness of certain implemented operations.