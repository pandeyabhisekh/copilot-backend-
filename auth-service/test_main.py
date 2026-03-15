import asyncio
import os
from dotenv import load_dotenv
import asyncpg
from passlib.context import CryptContext

load_dotenv()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def fix_login():
    DATABASE_URL = os.getenv("DATABASE_URL")
    if not DATABASE_URL:
        print("❌ DATABASE_URL not found in .env file!")
        return
    
    print("🔄 Connecting to database...")
    conn = await asyncpg.connect(DATABASE_URL)
    
    # Create fresh bcrypt hash
    new_hash = pwd_context.hash("Test@123")
    print(f"🔐 New hash created")
    
    # Update test user
    await conn.execute("""
        UPDATE users SET password = $1 WHERE email = 'test@example.com'
    """, new_hash)
    print(f"✅ Test user updated")
    
    # Update john user
    await conn.execute("""
        UPDATE users SET password = $1 WHERE email = 'john@example.com'
    """, new_hash)
    print(f"✅ John user updated")
    
    # Verify
    users = await conn.fetch("SELECT email, password FROM users")
    print("\n📊 Users in database:")
    for u in users:
        print(f"   📧 {u['email']}: {u['password'][:30]}...")
    
    await conn.close()
    print("\n✅ Password reset complete!")

if __name__ == "__main__":
    asyncio.run(fix_login())