import sqlite3

def register_user(username, password):
    connection = sqlite3.connect('./database.sqlite')
    c = connection.cursor()
    c.execute("SELECT id FROM Users WHERE username=?", (username,))
    if c.fetchone() is not None:
        return False
    c.execute("INSERT INTO Users (username, password) VALUES (?, ?)", (username, password))
    id = c.lastrowid
    c.execute("INSERT OR REPLACE INTO Score (user_id, game_id, points) VALUES (?, ?, ?), (?, ?, ?), (?, ?, ?)",
          (id, 1, 0, id, 2, 0, id, 3, 0))
    
    connection.commit()
    connection.close()
    return id


def login_user(username, password):
    connection = sqlite3.connect('./database.sqlite')
    c = connection.cursor()
    
    c.execute("SELECT id FROM Users WHERE username=? AND password=?", (username, password))
    user = c.fetchone()
    
    connection.close()
    return user[0] if user else False


def get_score(game_id):
    connection = sqlite3.connect('./database.sqlite')
    c = connection.cursor()
    
    c.execute("SELECT username, points FROM Score LEFT JOIN Users ON Score.user_id=Users.id "
              "WHERE Score.game_id=? AND Score.points > 0 ORDER BY Score.points DESC", (game_id,))
    
    return c.fetchall()


def get_score_by_userid(user_id):
    connection = sqlite3.connect('./database.sqlite')
    c = connection.cursor()
    
    c.execute("SELECT points FROM Score WHERE user_id=? ORDER BY game_id", (int(user_id),))
    fetched = c.fetchall()
    
    connection.close()
    return (fetched[0][0], fetched[1][0], fetched[2][0]) if len(fetched) >= 3 else (None, None, None)


def update_score(user_id, game_id, points):
    connection = sqlite3.connect('./database.sqlite')
    c = connection.cursor()
    
    c.execute("UPDATE Score SET points=? WHERE user_id=? AND game_id=?", (int(points), int(user_id), int(game_id)))
    
    connection.commit()
    connection.close()


def insert_news(title, text):
    connection = sqlite3.connect('./database.sqlite')
    c = connection.cursor()
    
    c.execute("INSERT INTO News (title, txt) VALUES (?, ?)", (title, text))
    
    connection.commit()
    connection.close()


def get_news():
    connection = sqlite3.connect('./database.sqlite')
    c = connection.cursor()
    
    c.execute("SELECT title, txt, time FROM News ORDER BY id DESC LIMIT 30")
    return_val = c.fetchall()
    
    connection.close()
    return return_val


def get_user(user_id):
    connection = sqlite3.connect('./database.sqlite')
    c = connection.cursor()
    
    c.execute("SELECT username, password FROM Users WHERE id=?", (user_id,))
    return_val = c.fetchone()
    
    connection.close()
    return return_val


def update_password(user_id, username, password):
    connection = sqlite3.connect('./database.sqlite')
    c = connection.cursor()
    
    c.execute("UPDATE Users SET password=? WHERE id=? AND username=?", (password, int(user_id), username))
    
    connection.commit()
    connection.close()


def ban_user(user_id):
    connection = sqlite3.connect('./database.sqlite')
    c = connection.cursor()
    
    c.execute("DELETE FROM Users WHERE id=?", (user_id,))
    c.execute("DELETE FROM Score WHERE user_id=?", (int(user_id),))
    
    connection.commit()
    connection.close()