import os
from databases import Database
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
database = Database(DATABASE_URL)

async def connect_db():
    await database.connect()
    print("✅ Database connected")

async def disconnect_db():
    await database.disconnect()
    print("✅ Database disconnected")