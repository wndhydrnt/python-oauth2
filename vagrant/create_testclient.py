import mysql.connector
from pymongo import MongoClient

client_id = "tc"
client_secret = "abc"
authorized_grants = ["authorization_code", "client_credentials", "password",
                     "refresh_token"]
authorized_response_types = ["code", "token"]
redirect_uris = ["http://127.0.0.1/index.html"]


def create_in_mongodb():
    client = MongoClient()

    db = client.testdb

    clients = db.clients

    client = clients.find_one({"identifier": client_id})

    if client is None:
        print("Creating test client in mongodb...")
        clients.insert({"identifier": client_id, "secret": client_secret,
                        "authorized_grants": authorized_grants,
                        "authorized_response_types": authorized_response_types,
                        "redirect_uris": redirect_uris})


def create_in_mysql():
    connection = mysql.connector.connect(host="127.0.0.1", user="root",
                                         passwd="", db="testdb")

    check_client = connection.cursor()
    check_client.execute("SELECT * FROM clients WHERE identifier = %s", (client_id,))
    client_data = check_client.fetchone()
    check_client.close()

    if client_data is None:
        print("Creating client in mysql...")
        create_client = connection.cursor()

        create_client.execute("""
            INSERT INTO clients (
                identifier, secret
            ) VALUES (
                %s, %s
            )""", (client_id, client_secret))

        client_id_in_mysql = create_client.lastrowid

        connection.commit()

        create_client.close()

        for authorized_grant in authorized_grants:
            create_grant = connection.cursor()

            create_grant.execute("""
                INSERT INTO client_grants (
                    name, client_id
                ) VALUES (
                    %s, %s
                )""", (authorized_grant, client_id_in_mysql))

            connection.commit()

            create_grant.close()

        for response_type in authorized_response_types:
            create_response_type = connection.cursor()

            create_response_type.execute("""
                INSERT INTO client_response_types (
                    response_type, client_id
                ) VALUES (
                    %s, %s
                )""", (response_type, client_id_in_mysql))

            connection.commit()

            create_response_type.close()

        for redirect_uri in redirect_uris:
            create_redirect_uri = connection.cursor()

            create_redirect_uri.execute("""
                INSERT INTO client_redirect_uris (
                    redirect_uri, client_id
                ) VALUES (
                    %s, %s
                )""", (redirect_uri, client_id_in_mysql))

            connection.commit()

            create_redirect_uri.close()


create_in_mysql()

create_in_mongodb()
