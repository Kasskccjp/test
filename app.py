import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # 查詢用戶持有的股票及餘額
    stocks = db.execute(
        """
        SELECT symbol, SUM(shares) as shares
        FROM transactions
        WHERE user_id = ?
        GROUP BY symbol
        HAVING SUM(shares) > 0
        """,
        session["user_id"]
    )
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

    # 獲取每隻股票的當前價格及總價值
    for stock in stocks:
        quote = lookup(stock["symbol"])
        if quote:
            stock["price"] = quote["price"]
            stock["total"] = stock["price"] * stock["shares"]
        else:
            stock["price"] = 0
            stock["total"] = 0

    # 計算投資組合總價值
    total = cash + sum(stock["total"] for stock in stocks)

    # 傳遞數據給模板
    return render_template("index.html", stocks=stocks, cash=cash, total=total)



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper().strip()
        shares = request.form.get("shares")

        # Validations
        if not symbol or not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("Invalid input", 400)

        stock = lookup(symbol)
        if not stock:
            return apology("Invalid symbol", 400)

        total_cost = stock["price"] * int(shares)
        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        if total_cost > user_cash:
            return apology("Not enough cash", 400)

        # Update the database
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", total_cost, session["user_id"])
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
            session["user_id"], symbol, shares, stock["price"]
        )

        return redirect("/")

    # Handle GET request
    symbol = request.args.get("symbol")
    stock = lookup(symbol) if symbol else None
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

    # If no stock is found, provide a default price of 0
    if not stock:
        stock = {"price": 0}

    return render_template("buy.html", symbol=symbol, stock=stock, cash=user_cash)

@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        # 從表單獲取 symbol
        symbol = request.form.get("symbol")
        if not symbol:
            return render_template("quote.html", stock=None, error="Must provide a symbol.")

        # 查詢股票
        stock = lookup(symbol.upper())
        if not stock:
            return render_template("quote.html", stock=None, error="Invalid Symbol.")

        # 成功返回股票資料
        return render_template("quote.html", stock=stock)

    # 處理 AJAX GET 請求
    symbol = request.args.get("symbol")
    if symbol:
        stock = lookup(symbol.upper())
        if stock:
            return {"price": stock["price"]}, 200
        else:
            return {"error": "Invalid Symbol"}, 400

    # 如果 symbol 無效或 GET 請求沒有參數
    return render_template("quote.html", stock=None)




@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT symbol, shares, price, timestamp FROM transactions WHERE user_id = ? ORDER BY timestamp DESC", session["user_id"])
    return render_template("history.html", transactions=transactions)



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")






@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # 確保用戶名和密碼輸入完整
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not username or not password or not confirmation:
            return apology("must provide all fields", 400)
        if password != confirmation:
            return apology("passwords do not match", 400)

        # 哈希密碼並插入到數據庫
        hash_pw = generate_password_hash(password)
        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash_pw)
        except:
            return apology("username already exists", 400)

        # 記錄用戶ID並重定向
        rows = db.execute("SELECT id FROM users WHERE username = ?", username)
        session["user_id"] = rows[0]["id"]
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # 驗證輸入數據
        if not symbol or not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("invalid input", 400)

        shares = int(shares)
        stock = db.execute(
            "SELECT SUM(shares) as shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol",
            session["user_id"], symbol,
        )

        # 檢查用戶是否有足夠的股票
        if not stock or stock[0]["shares"] < shares:
            return apology("not enough shares", 400)

        # 獲取股票價格並計算總價值
        price = lookup(symbol)["price"]
        total_value = shares * price

        # 更新用戶現金餘額
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", total_value, session["user_id"])

        # 插入交易記錄
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
            session["user_id"], symbol.upper(), -shares, price
        )

        return redirect("/")
    else:
        # 獲取用戶擁有的股票列表
        stocks = db.execute(
            "SELECT symbol, SUM(shares) as shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING shares > 0",
            session["user_id"],
        )

        # 為每隻股票附加價格和總價值
        for stock in stocks:
            stock_info = lookup(stock["symbol"])
            stock["price"] = stock_info["price"]
            stock["total_value"] = stock["shares"] * stock["price"]

        # 獲取 Portfolio 頁面傳遞過來的選中股票
        selected_symbol = request.args.get("symbol", None)

        return render_template("sell.html", stocks=stocks, selected_symbol=selected_symbol)


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Allow users to change their password."""
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        # 驗證當前密碼
        user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        if not user or not check_password_hash(user[0]["hash"], current_password):
            return apology("Invalid current password", 403)

        # 確認新密碼是否一致
        if new_password != confirm_password:
            return apology("New passwords do not match", 400)

        # 更新密碼
        new_hash = generate_password_hash(new_password)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hash, session["user_id"])

        flash("Password changed successfully!")
        return redirect("/")

    return render_template("change_password.html")
