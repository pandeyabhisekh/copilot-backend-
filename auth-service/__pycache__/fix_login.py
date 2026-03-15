# fix_login.py
import asyncio
import os
from dotenv import load_dotenv
import asyncpg
from passlib.context import CryptContext

load_dotenv()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def fix_login():
    DATABASE_URL = os.getenv("DATABASE_URL")
    conn = await asyncpg.connect(DATABASE_URL)
    
    # Create fresh bcrypt hash
    new_hash = pwd_context.hash("Test@123")
    print(f"🔐 New hash created")
    
    # Update test user
    await conn.execute("""
        UPDATE users SET password = $1 WHERE email = 'test@example.com'
    """, new_hash)
    
    # Update john user too
    await conn.execute("""
        UPDATE users SET password = $1 WHERE email = 'john@example.com'
    """, new_hash)
    
    print("✅ Passwords reset for test users")
    
    # Verify
    users = await conn.fetch("SELECT email, password FROM users")
    for u in users:
        print(f"📧 {u['email']}: {u['password'][:30]}...")
    
    await conn.close()

asyncio.run(fix_login())