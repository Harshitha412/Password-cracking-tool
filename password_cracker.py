import hashlib
import itertools
import time
import os
import threading

def generate_salt(length: int = 16) -> str:
    """Generates a random salt of the given length."""
    return os.urandom(length).hex()[:length]

def generate_hash(password: str, salt: str) -> str:
    """Hashes the password with the given salt using double SHA-256."""
    if len(salt) != 16:
        raise ValueError("Salt must be exactly 16 characters.")
    
    hash1 = hashlib.sha256((password + salt).encode()).hexdigest()
    return hashlib.sha256(hash1.encode()).hexdigest()

def crack_password(hash_value: str, salt: str, length: int, thread_count: int = 4):
    """Brute-force attacks a salted password hash using multithreading."""
    characters = "abcdefghijklmnopqrstuvwxyz"
    attempts = [0]  # Use a list to modify inside threads
    start_time = time.time()

    def worker(start, step):
        """Thread worker function that tries passwords in chunks."""
        for candidate in itertools.islice(itertools.product(characters, repeat=length), start, None, step):
            candidate_pw = ''.join(candidate)
            if generate_hash(candidate_pw, salt) == hash_value:
                time_taken = time.time() - start_time

                print("\n🔑 Generated Hash Value:", hash_value)
                print("🧂 Salt Used:", salt)
                print("✅ Cracked Password:", candidate_pw)
                print(f"⏳ Time Taken: {time_taken:.2f} seconds")
                print(f"🔢 Total Attempts: {attempts[0]}")
                os._exit(0)  # Force exit once found

            attempts[0] += 1

    # Create threads
    threads = []
    for i in range(thread_count):
        t = threading.Thread(target=worker, args=(i, thread_count))
        threads.append(t)
        t.start()

    # Wait for all threads to complete
    for t in threads:
        t.join()

    print("❌ Password not found")

if __name__ == "__main__":
    # Define a password and generate a salt
    password = "abcd"  # Example password
    salt = generate_salt()  # Generate a random salt

    # Generate and print the hashed password
    hashed_password = generate_hash(password, salt)

    print("\n Processing to crack password using multithreading...\n")
    crack_password(hashed_password, salt, len(password))
