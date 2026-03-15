import asyncio
import os
from dotenv import load_dotenv
import asyncpg
import hashlib

load_dotenv()

async def check_hash():
    DATABASE_URL = os.getenv("DATABASE_URL")
    conn = await asyncpg.connect(DATABASE_URL)
    
    # Get test user
    user = await conn.fetchrow("SELECT email, password FROM users WHERE email = 'test@example.com'")
    
    print(f"📧 Email: {user['email']}")
    print(f"🔐 Stored hash: {user['password']}")
    print(f"📏 Hash length: {len(user['password'])}")
    
    # Calculate expected hash
    SALT = "auth_service_fixed_salt_2024"
    test_password = "Test@123"
    expected_hash = hashlib.sha256((SALT + test_password).encode()).hexdigest()
    
    print(f"✨ Expected hash: {expected_hash}")
    print(f"✅ Match: {user['password'] == expected_hash}")
    
    # If not match, update it
    if user['password'] != expected_hash:
        print("\n🔄 Updating password hash...")
        await conn.execute("""
            UPDATE users SET password = $1 WHERE email = 'test@example.com'
        """, expected_hash)
        print("✅ Password updated!")
    
    await conn.close()

asyncio.run(check_hash())