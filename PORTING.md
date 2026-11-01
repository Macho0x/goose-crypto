# Porting

A byte taken from a shifted word stays an unchecked cast. A limb that used to narrow a wider sum is masked first. A length that the caller can exceed is checked, and Argon2 rejects a password, salt, secret, or associated data longer than 2^32-1 bytes.
