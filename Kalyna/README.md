# Kalyna  
  
Python implementation of Kalyna encryption algorithm.   
  
Code is divided into three files:  
 - `kalyna.py` contains all the parts of Kalyna algorithm: constants, transformations, key expansion algorithm, ciphering and deciphering algorithms.  
 - `benchmark.py` measures execution time of encryption with different block and key sizes.  
 - `tests.py`contains tests adopted from original paper.  
  
The implementation is very close to reference C implementation and does not use NumPy to full advantage. Due to this fact it is quite slow as seen below:  
  
**Benchmarking results:**  
  
 Encryption of 10 KB (Nb=2, Nk=2, Nr=10) takes: 23.343602418899536 s. 
 
 Encryption of 10 KB (Nb=2, Nk=4, Nr=14) takes: 32.04527711868286 s. 
 
 Encryption of 10 KB (Nb=8, Nk=8, Nr=18) takes: 41.299622535705566 s.

### \*Update\*

By using lookup table for byte multiplication a speed up of 13.5x was achieved.

**New benchmarking results:**  
  
Encryption of 100 KB (Nb=2, Nk=2, Nr=10) takes: 17.33861541748047 s.

Encryption of 100 KB (Nb=2, Nk=4, Nr=14) takes: 26.25675964355468 s.

Encryption of 100 KB (Nb=8, Nk=8, Nr=18) takes: 30.49541783332824 s.

