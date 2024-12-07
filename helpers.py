import requests

from flask import redirect, render_template, session
from functools import wraps


def apology(message, code=400):
    """Render message as an apology to user."""

    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [
            ("-", "--"),
            (" ", "-"),
            ("_", "__"),
            ("?", "~q"),
            ("%", "~p"),
            ("#", "~h"),
            ("/", "~s"),
            ('"', "''"),
        ]:
            s = s.replace(old, new)
        return s

    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function





def lookup(symbol):
    """Look up quote for symbol."""
    url = f"https://finance.cs50.io/quote?symbol={symbol.upper()}"
    try:
        # 發送 GET 請求
        response = requests.get(url)
        response.raise_for_status()  # 檢查 HTTP 錯誤

        # 解碼 JSON 數據
        quote_data = response.json()

        # 確保返回的 JSON 包含必要的字段
        if "companyName" in quote_data and "latestPrice" in quote_data and "symbol" in quote_data:
            return {
                "name": quote_data["companyName"],
                "price": quote_data["latestPrice"],
                "symbol": symbol.upper(),
            }
        else:
            return None
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return None
    except ValueError as e:
        print(f"Data parsing error: {e}")
        return None





def usd(value):
    """Format value as USD."""
    if isinstance(value, (int, float)):
        return f"${value:,.2f}"
    return value  # 如果不是數字，直接返回原始值以防止格式化錯誤

