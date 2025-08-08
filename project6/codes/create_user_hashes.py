import hashlib

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

if __name__ == "__main__":
    user_passwords = ['qwerty', 'mypassword', 'letmein']
    with open('user_hashes.txt', 'w') as f:
        for pwd in user_passwords:
            f.write(hash_password(pwd) + '\n')
    print("user_hashes.txt 已生成")