
from flask import Flask, render_template, request
import psycopg2
import re
import os

app = Flask(__name__)

DB_HOST = "db"
DB_NAME = os.getenv("POSTGRES_DB")
DB_USER = os.getenv("POSTGRES_USER")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD")



def get_db_connection():
    connection = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    return connection


@app.route("/dump", methods=["POST"])
def team_function():
    uuid = request.form.get('userUUID')
    vrfy = request.form.get('verify')

    if re.match(r'^[0-9]+$', vrfy, re.MULTILINE):
        connection = get_db_connection()
        cursor = connection.cursor()

        try:
            cursor.execute("""
                SELECT uuid, 'user'
                FROM users
                WHERE uuid = %s
                UNION ALL
                SELECT title, description
                FROM kopilkas
                WHERE owner_uuid = %s AND %s LIKE %s;
            """, (uuid, uuid, vrfy, '%notusual%'))

            result = cursor.fetchall()
            cursor.close()
            connection.close()

            return result, 200
        except:
            return "Some error", 500
    else:
        return "Nope", 500

@app.route("/", methods=["GET"])
def main():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=8081)
