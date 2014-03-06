from pymongo import MongoClient

client_id = "tc"

client = MongoClient()

db = client.testdb

clients = db.clients

client = clients.find_one({"client_id": client_id})

if client is None:
    print("Creating test client in mongodb...")
    clients.insert({"identifier": client_id, "secret": "abc",
                    "authorized_grants": ["authorization_code",
                                          "client_credentials", "password"],
                    "authorized_response_types": ["code", "implicit"],
                    "redirect_uris": ["http://127.0.0.1/index.html"]})
