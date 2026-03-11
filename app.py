from flask import Flask, request, render_template, redirect
from logger import log_api_call
from sequence_tracker import track_sequence, reset_sequence
from detector import detect_abuse
import csv

app = Flask(__name__)

cart = {}

# Product database
products_list = {
    "Phone": {"price": 20000, "img": "images/phone.jpg"},
    "Laptop": {"price": 50000, "img": "images/laptop.jpg"},
    "Tablet": {"price": 15000, "img": "images/tablet.jpg"}
}


@app.route("/")
def home():
    return render_template("login.html")


# ---------------- SECURITY CHECK ----------------
def process_request(user, api_name):

    if not user:
        return "User required"

    log_api_call(user, api_name)

    sequence = track_sequence(user, api_name)

    result = detect_abuse(sequence)

    if result != "Normal":
        return f"<h2 style='color:red;text-align:center;margin-top:200px'>{result}</h2>"

    return None


# ---------------- LOGIN ----------------
@app.route("/login", methods=["POST"])
def login():

    user = request.form.get("user")

    reset_sequence(user)

    response = process_request(user, "login")
    if response:
        return response

    cart[user] = []

    return redirect("/products?user=" + user)


# ---------------- PRODUCTS ----------------
@app.route("/products")
def products():

    user = request.args.get("user")

    response = process_request(user, "products")
    if response:
        return response

    products = []

    for name in products_list:
        products.append({
            "name": name,
            "price": products_list[name]["price"],
            "img": products_list[name]["img"]
        })

    return render_template("products.html", user=user, products=products)


# ---------------- ADD TO CART ----------------
@app.route("/add-to-cart")
def add_to_cart():

    user = request.args.get("user")
    item = request.args.get("item")

    response = process_request(user, "add-to-cart")
    if response:
        return response

    product = {
        "name": item,
        "price": products_list[item]["price"]
    }

    cart[user].append(product)

    return render_template("cart.html", user=user, item=product)


# ---------------- CHECKOUT ----------------
@app.route("/checkout")
def checkout():

    user = request.args.get("user")

    response = process_request(user, "checkout")
    if response:
        return response

    items = cart.get(user, [])

    total = sum(item["price"] for item in items)

    reset_sequence(user)

    return render_template("checkout.html", user=user, items=items, total=total)


# ---------------- PAYMENT ----------------
@app.route("/pay")
def pay():

    user = request.args.get("user")

    cart[user] = []

    return render_template("payment_success.html", user=user)


@app.route("/dashboard")
def dashboard():

    logs = []
    api_counts = {}

    with open("api_logs.csv") as f:
        reader = csv.reader(f)

        for row in reader:
            logs.append(row)

            api = row[1]

            if api not in api_counts:
                api_counts[api] = 0

            api_counts[api] += 1

    return render_template(
        "dashboard.html",
        logs=logs,
        api_counts=api_counts
    )


if __name__ == "__main__":
    app.run(debug=True)