#!/usr/bin/python3
from flask import Flask, make_response, request, render_template, redirect
import database
import jwt

app = Flask(__name__)

debugTestKey = "adminsecretpassword123!"
secret = "dgfvuedwkudsfdfsahjbdkcemh,dgvashkw"

def make_jwt(user_id, username):
    return jwt.encode({"user_id": user_id, "username": username}, secret, algorithm="HS256")

@app.route('/register', methods=["POST"])
def register():
    username, password = request.form["username"], request.form["password"]
    user_id = database.register_user(username, password)
    if not user_id:
        return render_template("register.html", show_error=True)
    resp = make_response(redirect('/'))
    return resp

@app.route('/login', methods=["POST"])
def login():
    username, password = request.form["username"], request.form["password"]
    if user_id := database.login_user(username, password):
        resp = make_response(redirect('choose_game.html'))
        resp.set_cookie("session", make_jwt(user_id, username))
        return resp
    else:
        return make_response(redirect('/'))

@app.route('/logout', methods=["GET"])
def logout():
    resp = make_response(redirect('/'))
    resp.delete_cookie("session")
    return resp

@app.route('/score', methods=["POST"])
def score():
    game_id, score, time = request.json["game_id"], request.json["score"], request.json["time"]
    try:
        s = jwt.decode(request.cookies['session'], secret, algorithms=["HS256"])
        user_id, username = s["user_id"], s["username"]
    except:
        return make_response(redirect('/logout'))
    if score > 100 > time:
        database.ban_user(int(user_id))
        database.insert_news("User  banned", f"User  {username} has been banned for cheating")
        return make_response({"status": "cheating"}, 403)
    database.update_score(user_id, game_id, score)
    resp = make_response({"status": "ok"}, 200)
    return resp

@app.route('/change_password', methods=["POST"])
def change_password():
    password = request.form["password"]
    try:
        s = jwt.decode(request.cookies['session'], secret, algorithms=["HS256"])
        user_id, username = s["user_id"], s["username"]
    except:
        return make_response(redirect('/logout'))
    database.update_password(user_id, username, password)
    return make_response(redirect('/profile.html'))

@app.route('/')
def login_page():
    return render_template("login.html")

@app.route('/register.html')
def register_page():
    return render_template("register.html")

@app.route('/choose_game.html')
def choose_game_page():
    return render_template("choose_game.html")

@app.route('/profile.html')
def profile():
    try:
        s = jwt.decode(request.cookies['session'], secret, algorithms=["HS256"])
        user_id, username = int(s["user_id"]), s["username"]
        password = database.get_user(user_id)[1]
    except:
        return make_response(redirect('/logout'))
    score = database.get_score_by_userid(user_id)
    return render_template("profile.html", user_id=user_id, username=username, password=password, score=score)

@app.route('/news.html')
def news_page():
    stored_news = database.get_news()
    if 'session' not in request.cookies:
        return make_response(redirect('/'))
    try:
        jwt.decode(request.cookies['session'], secret, algorithms=["HS256"])
    except:
        return make_response(redirect('/logout'))
    resp = make_response(render_template("news.html", news=stored_news))
    resp.headers['Cache-Control'] = 'no-cache'
    return resp

@app.route('/game/<game_id>')
def game_page(game_id):
    return render_template(f"game_{game_id}.html", game_id=game_id)

@app.route('/scoreboard/<int:game_id>')
def scoreboard_page(game_id):
    return render_template("scoreboard.html", game_id=int(game_id), score=database.get_score(game_id))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=4242)