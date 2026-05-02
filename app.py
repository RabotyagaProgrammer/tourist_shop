import hashlib
import secrets
import sqlite3
import time
import urllib.parse
from urllib.parse import urlparse, unquote
from functools import wraps
import os
import jwt
from flask import Flask, render_template, request, jsonify, g

app = Flask(__name__)

JWT_SECRET = "funkymonkey"
JWT_ALGORITHM = "HS256"
JWT_TTL = 60 * 60 * 24
UPLOAD_FOLDER = "uploads"
MAX_CONTENT_LENGTH = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "txt", "pdf"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

block_schemes = ["file", "gopher", "expect", "php", "dict", "ftp", "glob", "data"]
block_host = [ "127.0.0.1", "localhost", "localhost.localdomain", "local", "localdomain", 
              "::1", "ip6-localhost", "ip6-loopback", "0.0.0.0", "127.0.0.0", 
              "127.0.0.2", "127.0.0.3", "127.255.255.255", "127.0.0.255", "169.254.0.0", 
              "169.254.1.1", "169.254.255.255", "fe80::1", "fe80::", "localhost.local", 
              "localhost6", "localhost6.localdomain6", "ip6-localnet", "ip6-mcastprefix", 
              "ip6-allnodes", "ip6-allrouters", "255.255.255.255", "224.0.0.1", 
              "224.0.0.2", "ff02::1", "ff02::2", "local", "localhost.", 
              "localhost.localdomain.", "broadcasthost", "gateway", "router"]

db = sqlite3.connect("utils/sqlite.db", check_same_thread=False)
db.row_factory = sqlite3.Row


def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()
    
def get_request_data():
    data = request.get_json()
    if data is not None:
        return data
    return request.form


def issue_token(username, role):
    return jwt.encode(
        {"sub": username, "role": role, "iat": int(time.time()), "exp": int(time.time()) + JWT_TTL},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("token")
        if not token:
            return jsonify(error="authentication required"), 401
        try:
            g.user = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.InvalidTokenError:
            return jsonify(error="invalid token"), 401
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    @auth_required
    def wrapper(*args, **kwargs):
        if g.user.get("role") != "admin":
            return jsonify(error="admin access required"), 403
        return f(*args, **kwargs)
    return wrapper


def csrf_protect(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        ct = request.cookies.get("_csrf", "")
        ft = request.headers.get("X-CSRF-Token", "") or request.form.get("_csrf", "")
        if not ct or ct != ft:
            return jsonify(error="csrf token mismatch"), 403
        return f(*args, **kwargs)
    return wrapper


def set_auth_cookies(resp, username, role):
    token = issue_token(username, role)
    resp.set_cookie("token", token, httponly=True, samesite="None", max_age=JWT_TTL)
    resp.set_cookie("_csrf", secrets.token_hex(32), httponly=False, samesite="None", max_age=JWT_TTL)
    return resp


def is_allowed_file(filename):
    if "." in filename:
        ext = filename.rsplit(".", 1)[1].lower()
        return ext in ALLOWED_EXTENSIONS
    return False


@app.route("/api/auth/register", methods=["POST"])
def register():
    data = get_request_data()
    username = data.get("username", "").strip().lower()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not username or not email or len(password) < 4:
        return jsonify(error="username, email and password (4+ chars) required"), 400

    try:
        db.execute(
            "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, 'user')",
            (username, email, hash_password(password)),
        )
        db.commit()
        db.execute(
            "INSERT INTO discount (username, discount, add_old_orders, orders_count) VALUES (?, 0, 1, 0)",
            (username,),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="registration failed"), 400

    resp = jsonify(ok=True, user=username)
    return set_auth_cookies(resp, username, "user"), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = get_request_data()
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")

    row = db.execute(
        "SELECT username, role FROM users WHERE username = ? AND password = ?",
        (username, hash_password(password)),
    ).fetchone()

    if not row:
        return jsonify(error="invalid credentials"), 401

    resp = jsonify(ok=True, user=row["username"], role=row["role"])
    return set_auth_cookies(resp, row["username"], row["role"])


@app.route("/api/auth/logout", methods=["POST"])
@auth_required
@csrf_protect
def logout():
    resp = jsonify(ok=True)
    resp.delete_cookie("token")
    resp.delete_cookie("_csrf")
    return resp


@app.route("/api/me")
@auth_required
def me():
    row = db.execute(
        "SELECT username, email, role FROM users WHERE username = ?",
        (g.user["sub"],),
    ).fetchone()
    if not row:
        return jsonify(error="user not found"), 404
    return jsonify(user=row["username"], email=row["email"], role=row["role"])


@app.route("/api/admin/users")
@admin_required
def list_users():
    rows = db.execute("SELECT username, email, role FROM users").fetchall()
    return jsonify(users=[dict(r) for r in rows])


@app.route("/api/admin/create_product", methods=["POST"])
@admin_required
@csrf_protect
def create_product():
    data = get_request_data()
    description = data.get("description", "")
    price = data.get("price", "")
    reviews = data.get("reviews", "")

    if not description or not price:
        return jsonify(error="Description and Price required"), 400
    
    if type(price) is not int:
        return jsonify(error="Price must be an integer"), 400
        
    if price <= 0:
        return jsonify(error="Price cannot be negative"), 400
    
    if reviews:
        decode_reviews = unquote(reviews)
        parsed = urlparse(decode_reviews)
        scheme = parsed.scheme.lower()
        host = parsed.netloc.lower()
        if parsed.username or parsed.password:
            return jsonify(error="Basic authentication in URL is not allowed"), 400
        if scheme in block_schemes:
            return jsonify(error="Input scheme is forbidden"), 400
        if host in block_host:
            return jsonify(error="Input hostname is forbidden"), 400
        try:
            target = urllib.request.urlopen(reviews)
            return jsonify({"message":"Product created successfully",
                    "description":description,
                    "price":price,
                    "reviews":target.read().decode('utf-8')}), 201
        except Exception as e:
            return jsonify({"error": str(e), "message": "Failed to create product"}), 400

    db.execute("INSERT INTO products (description, price) VALUES (?, ?)",
            (description, price))
    db.commit()
    

@app.route("/api/admin/upload", methods=["POST"])
@admin_required
@csrf_protect
def upload_file():
    files = []
    try:
        files = os.listdir(UPLOAD_FOLDER)
    except:
        pass

    if "file" not in request.files:
        return jsonify(error="no file selected"), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify(error="filename is empty"), 400

    if not is_allowed_file(file.filename):
        return jsonify(error="file extension not allowed"), 400

    filename = file.filename.replace("../", "").replace("..\\", "")

    save_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(save_path)

    return jsonify({"message": "file has been successfully uploaded"}), 200


@app.route("/api/admin/view", methods=["GET"])
@admin_required
def view_file():
    files = []
    try:
        files = os.listdir(UPLOAD_FOLDER)
    except:
        pass

    filename = request.args.get("file", "")

    if not filename:
        return jsonify(error="no file name specified"), 400

    filename = filename.replace("../", "").replace("..\\", "")
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            result = {"ok": True, "message": content}

        return jsonify(**result)

    except FileNotFoundError:
        return jsonify(error="file not found"), 400

    except Exception as e:
        return jsonify(error=f"error reading file {str(e)}"), 400


@app.route("/api/settings/password", methods=["POST"])
@auth_required
@csrf_protect
def change_password():
    data = get_request_data()
    pw = data.get("new_password", "")
    if len(pw) < 4:
        return jsonify(error="password must be at least 4 characters"), 400

    username = g.user["sub"]
    db.execute("UPDATE users SET password = ? WHERE username = ?", (hash_password(pw), username))
    db.commit()

    result = {"ok": True, "message": "password updated"}
    
    return jsonify(**result)


@app.route("/api/discount", methods=["GET"])
@auth_required
def check_discount():
    row = db.execute(
        "SELECT username, discount, add_old_orders, orders_count FROM discount WHERE username = ?",
        (g.user["sub"],),
    ).fetchone()
    if not row:
        return jsonify(error="user not found"), 404
    return jsonify(user=row["username"], discount=row["discount"], add_old_orders=row["add_old_orders"], orders_count=row["orders_count"])


@app.route("/api/bind_old_orders", methods=["POST"])
@auth_required
@csrf_protect
def bind_old_orders():
    data = get_request_data()
    phone = data.get("phone_number", "")
    rows = db.execute("SELECT id FROM orders where phone_number = ? and is_registered = 0", (phone,)).fetchall()
    row = db.execute(
        "SELECT username, discount, add_old_orders, orders_count FROM discount WHERE username = ?",
        (g.user["sub"],),
    ).fetchone()
    orders_count = row["orders_count"] + len(rows)
    if len(rows) > 0:
        db.execute("UPDATE orders SET is_registered = 1 WHERE phone_number = ? and is_registered = 0", (phone,))
        db.commit()
    discount = 0
    if orders_count > 20:
        discount = 25
    elif orders_count > 15:
        discount = 20
    elif orders_count > 10:
        discount = 15
    elif orders_count > 5:
        discount = 10    
    username = g.user["sub"]
    db.execute("UPDATE discount SET orders_count = ?, discount = ?, add_old_orders = 0 WHERE username = ?", (orders_count, discount, username,))
    db.commit()
    
    return jsonify(message="discount info updated")


@app.route('/discount')
def index():
    phone_bound = ""
    return render_template('discount.html', phone_bound=phone_bound)


class ServiceMiddleware:
    def __init__(self, wsgi):
        self.wsgi = wsgi
        self.boot = time.time()
        self.request_count = 0

    def __call__(self, environ, start_response):
        self.request_count += 1
        path = environ["PATH_INFO"]

        if path == "/health":
            start_response("200 OK", [("Content-Type", "application/json")])
            return [b'{"status":"ok"}']

        if path == "/metrics":
            body = f'{{"uptime":{int(time.time() - self.boot)},"requests":{self.request_count}}}'.encode()
            start_response("200 OK", [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
            ])
            return [body]

        if path == "/go":
            qs = environ.get("QUERY_STRING", "")
            target = urllib.parse.parse_qs(qs).get("url", ["/"])[0]
            target = urllib.parse.unquote(target)
            start_response("302 Found", [
                ("Location", target),
                ("Content-Length", "0"),
            ])
            return [b""]

        return self.wsgi(environ, start_response)


app.wsgi_app = ServiceMiddleware(app.wsgi_app)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
