from pymongo import MongoClient

client_id = "tc"

client = MongoClient()

db = client.testdb

clients = db.clients

client = clients.find_one({"client_id": client_id})

if client is None:
    print("Creating test client in mongodb...")
    clients.insert({"client_id": client_id, "client_secret": "abc", "redirect_uris": ["http://127.0.0.1/index.html"]})
