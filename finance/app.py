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
    # Get user's stocks and shares from the database
    user_id = session["user_id"]
    user_stocks = db.execute(
        "SELECT symbol, SUM(shares) AS total_shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0",
        user_id,
    )

    # Prepare data for the HTML table
    table_data = []
    total_value = 0

    for stock in user_stocks:
        symbol = stock["symbol"]
        shares = stock["total_shares"]

        # Get current stock information
        stock_info = lookup(symbol)
        price = stock_info["price"]
        total_stock_value = price * shares
        total_value += total_stock_value

        # Format for better table
        new_symbol = symbol.upper()
        new_price = usd(price)
        new_total_stock_value = usd(total_stock_value)

        table_data.append(
            {
                "Symbol": new_symbol,
                "Shares": shares,
                "Current Price": new_price,
                "Total Value": new_total_stock_value,
            }
        )

    # Get user's current cash balance from the database
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
    new_user_cash = usd(user_cash)
    total_value += user_cash
    new_total_value = usd(total_value)

    # Render the HTML table
    return render_template(
        "index.html",
        table_data=table_data,
        cash=new_user_cash,
        new_total_value=new_total_value,
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # Retrieve stock symbol and shares from the form
    if request.method == "POST":
        stockSymbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")

        # Validate stock symbol and shares input
        if not stockSymbol:
            return apology("Missing Symbol", 400)
        if lookup(stockSymbol) == None:
            return apology("Invalid Symbol", 400)

        if not shares:
            return apology("Missing Shares", 400)

        if not shares.isdigit():
            return apology("Invalid number of Shares", 400)

        shares = int(shares)
        # Retrieve current stock price and calculate total cost
        search = lookup(stockSymbol)
        share_price = search["price"]
        shares_to_buy = share_price * shares

        # Check if user has sufficient funds
        user_id = session["user_id"]
        account_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0][
            "cash"
        ]

        if shares_to_buy > account_cash:
            # Return an error if the user cannot afford the shares
            return apology("Can't Afford", 400)
        else:
            # Deduct purchase cost from user's account
            new_cash = account_cash - shares_to_buy

            db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, user_id)

            # Add bought shares to the transactions table
            db.execute(
                "INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                user_id,
                stockSymbol,
                shares,
                share_price,
            )

            # Add bought shares to the history table
            db.execute(
                "INSERT INTO history_bought (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                user_id,
                stockSymbol,
                shares,
                share_price,
            )

            # Display success message and update the portfolio
            flash("Bought!")
            return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Retrieve user's transactions info
    user_id = session["user_id"]

    user_bought_transactions = db.execute(
        "SELECT symbol, shares, price, timestamp FROM history_bought WHERE user_id = ?",
        user_id,
    )
    user_sold_transactions = db.execute(
        "SELECT symbol, shares, price, timestamp FROM history_sold WHERE user_id = ?",
        user_id,
    )

    history_data = []

    # Process bought transactions
    for stock in user_bought_transactions:
        history_data.append(format_transaction(stock))

    # Process sold transactions
    for stock in user_sold_transactions:
        formatted_transaction = format_transaction(stock)
        formatted_transaction[
            "Shares"
        ] *= -1  # Update shares to negative for sold transactions
        history_data.append(formatted_transaction)

    # Sort history_data by 'Transacted' timestamp
    history_data = sorted(history_data, key=lambda x: x["Transacted"])

    return render_template("history.html", history_data=history_data)


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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        stockSymbol = request.form.get("symbol")
        if not stockSymbol:
            return apology("Missing Symbol")
        search = lookup(stockSymbol)
        if search != None:
            return render_template("quoted.html", quote=search)
        else:
            return apology("Invalid Symbol")
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # Registering a user when POST method
    if request.method == "POST":
        name = request.form.get("username").split()
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Validate username, check if already exists
        if not name:
            return apology("Name is empty", 400)

        # Validate password and confirmation
        elif not password or not confirmation:
            return apology("Password is empty", 400)

        elif password != confirmation:
            return apology("Passwords dont match", 400)

        # Hash the password and add user to the database
        hash_password = generate_password_hash(password)

        # Checking if username exists in the database
        check_username_exist = db.execute("SELECT * FROM users WHERE username = :name", name=name)
        if check_username_exist:
            return apology("Username already exists", 400)

        # Include register into our database
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", name, hash_password)

        # return render_template("register.html")
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    user_id = session["user_id"]

    # Fetch user's owned shares
    user_shares = db.execute(
        "SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol", (user_id)
    )

    list_of_user_shares = []

    for share in user_shares:
        user_share_symbol = share["symbol"].upper()
        list_of_user_shares.append(user_share_symbol)

    if request.method == "POST":
        stockSymbol = request.form.get("symbol")
        shares = request.form.get("shares")
        user_share_symbol = db.execute(
            "SELECT SUM(shares) AS total_shares FROM transactions WHERE user_id = ? AND symbol = ?",
            user_id,
            stockSymbol,
        )

        # Validate input fields
        if not stockSymbol:
            return apology("Missing Symbol")

        if not shares:
            return apology("Missing Shares")

        shares = int(shares)

        selected_share = user_share_symbol[0]["total_shares"]

        # Check if the user has enough shares to sell
        if shares > selected_share:
            return apology("Too Many Shares")

        # Retrieve share price and calculate total selling price
        search = lookup(stockSymbol)
        share_price = search["price"]
        shares_to_sell = share_price * shares

        # Update user's cash balance
        account_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0][
            "cash"
        ]
        new_cash = account_cash + shares_to_sell
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, user_id)

        # Record the sold shares in the history table
        db.execute(
            "INSERT INTO history_sold (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
            user_id,
            stockSymbol,
            shares,
            share_price,
        )

        # Update the transactions table with the remaining shares
        shares_to_sell_rows = db.execute(
            "SELECT id, shares FROM transactions WHERE user_id = ? AND symbol = ?",
            user_id,
            stockSymbol,
        )
        remaining_shares = shares

        for row in shares_to_sell_rows:
            if remaining_shares <= 0:
                break

            if row["shares"] >= remaining_shares:
                db.execute(
                    "UPDATE transactions SET shares = shares - ? WHERE id = ?",
                    remaining_shares,
                    row["id"],
                )
                remaining_shares = 0
            else:
                remaining_shares -= row["shares"]
                db.execute("DELETE FROM transactions WHERE id = ?", row["id"])

        flash("Sold!")
        return redirect("/")

    else:
        return render_template("sell.html", list_of_user_shares=list_of_user_shares)


def format_transaction(transaction):
    symbol = transaction["symbol"]
    shares = transaction["shares"]
    price = transaction["price"]
    transacted = transaction["timestamp"]

    # Format price
    new_price = usd(price)

    return {
        "Symbol": symbol,
        "Shares": shares,
        "Price": new_price,
        "Transacted": transacted,
    }


@app.route("/settings", methods=["GET", "POST"])
@login_required
def change_users_password():
    if request.method == "POST":
        user_id = session["user_id"]
        user_password = db.execute("SELECT hash FROM users WHERE id = ?", user_id)[0][
            "hash"
        ]
        bad_characters = [";", ":", "!", "*", " "]

        password = request.form.get("password")
        check_password = check_password_hash(user_password, password)

        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        if not password:
            return apology("Insert old password")
        if check_password == False:
            return apology("Insert Correct Password")

        if password == new_password:
            return apology("Cannot be the same password")

        for char in bad_characters:
            if char in new_password:
                return apology("Invalid characters")

        if not new_password or new_password != confirmation:
            return apology("Invalid password")

        else:
            hash_new_password = generate_password_hash(new_password)
            db.execute(
                "UPDATE users SET hash = ? WHERE id = ?", hash_new_password, user_id
            )

            flash("Successfully changed password!")
            return index()

    else:
        return render_template("settings.html")
