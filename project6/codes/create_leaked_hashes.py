import hashlib

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

if __name__ == "__main__":
    leaked_passwords = ['123456', 'password', 'letmein', 'qwerty']
    with open('leaked_hashes.txt', 'w') as f:
        for pwd in leaked_passwords:
            f.write(hash_password(pwd) + '\n')
    print("leaked_hashes.txt 已生成")