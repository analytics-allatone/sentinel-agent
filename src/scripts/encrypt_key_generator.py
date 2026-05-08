from cryptography.fernet import Fernet
"""
DO NOT RUN THIS SCRIPT
"""
def generate_key():
    key = Fernet.generate_key()
    print(key.decode())

    
if __name__ == "__main__":

    generate_key()