import mysql.connector
import heapq  # Dijkstra's Algorithm
from collections import deque
import re
from flask import jsonify
import random
import string
import bcrypt
import stripe
import os
import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')


# ✅ Load environment variables from .env file
load_dotenv()

# ✅ Configure Logging
logging.basicConfig(level=logging.INFO)

# ✅ Retrieve Secret Keys
SECRET_KEY = os.getenv("SECRET_KEY")  # Load SECRET_KEY from .env
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")  # Load STRIPE_SECRET_KEY from .env
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY")  # Load STRIPE_SECRET_KEY from .env

if not SECRET_KEY:
    logging.error("❌ SECRET_KEY is missing in the environment file!")

if not STRIPE_SECRET_KEY:
    logging.error("❌ STRIPE_SECRET_KEY is missing in the environment file!")

    # Directory to store uploaded images
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Ensure folder exists

# Allowed file extensions for images
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ✅ Secure Database Connection
def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=os.getenv("DB_HOST", "localhost"),
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASSWORD", ""),
            database=os.getenv("DB_NAME", "onlinefooddelivery")
        )
        if connection.is_connected():
            return connection
        else:
            logging.error("Database connection failed but no exception was raised")
            return None
    except mysql.connector.Error as err:
        logging.error(f"Database connection error: {err}")
        return None

# ✅ Secure Password Handling
def hash_password(password):
    """Generate a hashed password."""
    if password is None:
        logging.error("❌ Error: Password is None!")
        return None
    return generate_password_hash(password)

def verify_password(stored_hash, password):
    """Verify if the entered password matches the stored hash."""
    return check_password_hash(stored_hash, password)

# ✅ Example Usage
if __name__ == "__main__":
  
    if SECRET_KEY:
        logging.info(f"✅ SECRET_KEY: {SECRET_KEY[:8]}******** (Loaded Successfully)")
else:
    logging.error("❌ SECRET_KEY not found or is None")
    logging.info(f"✅ STRIPE_SECRET_KEY: {STRIPE_SECRET_KEY[:8]}******** (Loaded Successfully)")

    test_password = "Secure@1234"  # Example password
    stored_hash = hash_password(test_password)  # Hash the password
    is_valid = verify_password(stored_hash, test_password)  # Verify password
    logging.info(f"Password is valid: {is_valid}")  # Output: True if correct


# ✅ Enable CSRF protection
csrf = CSRFProtect(app)  

# Load the API key from the environment variable
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# Check if the key is loaded correctly
if stripe.api_key:
    print("Stripe API key loaded successfully!")
else:
    print("Error: Stripe API key not found.")


# ✅ Sample menu items for different restaurants
menus = {
    1: [{"name": "Pizza", "price": 10}, {"name": "Burger", "price": 8}, {"name": "Pasta", "price": 12}],
    2: [{"name": "Sushi", "price": 15}, {"name": "Ramen", "price": 12}, {"name": "Tempura", "price": 14}],
    3: [{"name": "Biryani", "price": 10}, {"name": "Tandoori Chicken", "price": 12}, {"name": "Paneer Butter Masala", "price": 9}]
}


# ✅ Fetch restaurant and user locations
def fetch_locations():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    
    # Fetch restaurant locations
    cursor.execute("SELECT restaurant_id AS id, name, latitude, longitude FROM Restaurant")
    restaurants = {row["id"]: row for row in cursor.fetchall()}
    
    # Fetch user locations
    cursor.execute("SELECT user_id AS id, name, latitude, longitude FROM User")
    users = {row["id"]: row for row in cursor.fetchall()}
    
    locations = {**restaurants, **users}  # Merge both dictionaries
    connection.close()
    return locations

# ✅ Fetch roads (edges) between restaurants and users
def fetch_graph():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    
    cursor.execute("SELECT from_location, to_location, distance FROM Roads")
    graph = {}
    
    for row in cursor.fetchall():
        if row["from_location"] not in graph:
            graph[row["from_location"]] = {}
        graph[row["from_location"]][row["to_location"]] = row["distance"]

        for node in graph.keys():
           if node not in graph:
               graph[node] = {}  # Ensure all nodes are included

    
    connection.close()
    return graph

# ✅ Dijkstra’s Algorithm Using MySQL Data
def dijkstra(start, end):
    locations = fetch_locations()  # Get locations first
    graph = fetch_graph()
    
    # Rest of your implementation
    
    priority_queue = [(0, start)]
    distances = {node: float('inf') for node in graph}
    distances[start] = 0
    path = {}

    while priority_queue:
        current_distance, current_node = heapq.heappop(priority_queue)

        if current_node == end:
            break

        for neighbor, weight in graph.get(current_node, {}).items():
            distance = current_distance + weight
            if distance < distances[neighbor]:
                distances[neighbor] = distance
                heapq.heappush(priority_queue, (distance, neighbor))
                path[neighbor] = current_node

    if distances[end] == float('inf'):
        return jsonify({"error": "No path found"}), 404


    # ✅ Reconstruct the shortest path
    shortest_path = []
    node = end
    while node in path:
        shortest_path.insert(0, locations[node]["name"])
        node = path[node]
    shortest_path.insert(0, locations[start]["name"])

    return shortest_path, distances[end]


@app.route("/get-delivery-route", methods=["GET"])
def get_delivery_route():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    # Get latest order details
    cursor.execute("SELECT user_id, restaurant_id FROM Orders WHERE status = 'Out for Delivery' ORDER BY order_date DESC LIMIT 1")
    order = cursor.fetchone()

    if not order:
        return jsonify({"error": "No active deliveries"}), 404

    # Get restaurant location
    cursor.execute("SELECT latitude, longitude FROM Restaurant WHERE restaurant_id = %s", (order["restaurant_id"],))
    restaurant = cursor.fetchone()

    # Get customer location
    cursor.execute("SELECT latitude, longitude FROM User WHERE user_id = %s", (order["user_id"],))
    customer = cursor.fetchone()

    connection.close()

    return jsonify({
        "start": {"lat": restaurant["latitude"], "lng": restaurant["longitude"]},
        "end": {"lat": customer["latitude"], "lng": customer["longitude"]}
    })

# ✅ Test Delivery Route Calculation
start_location = 1  # Example: Havana multicuisine restaurant
end_location = 1    # Example: Hemasri's address
route, distance = dijkstra(start_location, end_location)
print(f"🚀 Shortest Route: {route} (Distance: {distance} km)")

# Home Page
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('restaurants'))  # Redirect to restaurants if logged in
    return redirect(url_for('login'))  # Redirect to login if not logged in

@app.route('/base')
def base():
    return render_template('base.html')  # Render base.html directly

# ✅ Hashing for Quick Food Lookups
class FoodHashing:
    def __init__(self):
        self.food_data = {}

    def add_food(self, food_name, details):
        hash_key = hash(food_name)
        self.food_data[hash_key] = details

    def get_food(self, food_name):
        hash_key = hash(food_name)
        return self.food_data.get(hash_key, "Food item not found")

# ✅ Queue for Order Processing
class OrderQueue:
    def __init__(self):
        self.queue = deque()

    def add_order(self, order):
        self.queue.append(order)
        print(f"✅ Order added: {order}")

    def process_order(self):
        if self.queue:
            processed_order = self.queue.popleft()
            print(f"🚀 Processing Order: {processed_order}")
        else:
            print("❌ No orders to process")

# ✅ Stack for Navigation History
class NavigationStack:
    def __init__(self):
        self.stack = []

    def navigate(self, page):
        self.stack.append(page)
        print(f"📍 Navigated to {page}")

    def go_back(self):
        if len(self.stack) > 1:
            self.stack.pop()
            print(f"🔙 Back to {self.stack[-1]}")
        else:
            print("❌ No previous page to go back to")

    
            # ✅ Routes for HTML Pages
@app.route("/delivery-tracking")
def delivery_tracking():
    return render_template("delivery tracking.html")

@app.route("/search-food")
def search_food():
    food_name = request.args.get("name", "")
    food_details = food_hashing.get_food(food_name)
    return jsonify({"details": food_details})

@app.route("/search")
def search_page():
    return render_template("search.html")

@app.route("/get-orders")
def get_orders():
    orders = list(order_queue.queue)  # Convert deque to list
    return jsonify({"orders": [{"id": i + 1, "status": order} for i, order in enumerate(orders)]})

@app.route('/get_image')
def get_image():
    image_url = url_for('static', filename='images/your_actual_image.jpg')
    return jsonify({"image": image_url})

@app.route('/admin')
def admin_dashboard():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    cursor = None
    connection = None
    try:
        # Ensure the connection is established correctly
        connection = mysql.connector.connect(
            host='localhost',  # Use your actual MySQL host here, e.g., 'localhost'
            user='root',  # Replace with your actual MySQL username
            password='mamu@1806',  # Replace with your actual MySQL password
            database='onlinefooddelivery'  # Replace with your actual database name
        )
        
        # Create a cursor to execute queries
        cursor = connection.cursor()
        
        # Execute the query to fetch restaurants
        cursor.execute("SELECT restaurant_id, name, location, image_url FROM Restaurant")
        restaurants = cursor.fetchall()
        
        # Debugging line to check data
        print(f"Restaurants: {restaurants}")
        
        # Now, convert each tuple into a dictionary
        restaurants_dict = []
        for restaurant in restaurants:
            restaurant_dict = {
                'id': restaurant[0],  # Assuming the first column is 'restaurant_id'
                'name': restaurant[1],  # Assuming the second column is 'name'
                'location': restaurant[2],  # Assuming the third column is 'location'
                'image_url': restaurant[3]  # Assuming the fourth column is 'image_url'
            }
            restaurants_dict.append(restaurant_dict)
        
        # Use the dictionary list instead of the tuple list
        restaurants = restaurants_dict
        
    except mysql.connector.Error as err:
        print(f"Error fetching restaurants from database: {err}")
        restaurants = []
    finally:
        # Only close the cursor if it was created successfully
        if cursor:
            cursor.close()
        if connection:
            connection.close()
    
    return render_template('admin_dashboard.html', restaurants=restaurants)

# Initialize Data Structures
food_hashing = FoodHashing()
order_queue = OrderQueue()

# ✅ User Management
class UserManager:
    def __init__(self, name, email, phone, password, address):
        self.name = name
        self.email = email
        self.phone = phone
        self.password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()  # 🛡️ Hash password5
        self.address = address

    def register(self):
        if not self.name.isalpha():
            return {"error": "Invalid Name."}
        
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, self.email):
            return {"error": "Invalid Email format."}
        
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT email FROM User WHERE email = %s", (self.email,))
        if cursor.fetchone():
             return {"error": "Email already exists."}
        
        cursor.execute("INSERT INTO User (name, email, phone, password, address) VALUES (%s, %s, %s, %s, %s)", 
                       (self.name, self.email, self.phone, self.password, self.address))
        connection.commit()
        connection.close()
        return {"message": "Registration successful!"}


# ✅ Flask Routes
@app.route('/')
def dashboard():
    return "Welcome to Online Food Delivery Dashboard"

# Define the form class using Flask-WTF
class AdminLoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM user WHERE email = %s AND is_admin = 1", (email,))
        admin = cursor.fetchone()
        connection.close()

        print(f"Admin: {admin}")
        print(f"Entered password: {password}, Stored password: {admin['password'] if admin else 'N/A'}")

        if admin and password == admin['password']:
            session['admin_id'] = admin['user_id']
            session['admin_name'] = admin['name']
            flash('Admin logged in successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials or not an admin.', 'danger')

    return render_template('admin_login.html', form=form)

# ✅ Admin Class for Restaurant & Order Management
class Admin:
    @staticmethod
    def list_restaurants():
        connection = get_db_connection()
        if not connection:
            return "❌ Database Connection Failed"
        
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT restaurant_id, name, location, image_url FROM Restaurant")
        restaurants = cursor.fetchall()
        connection.close()
        
        return restaurants  # Returns a list of dictionaries

    @staticmethod
    def add_restaurant(name, location, image_url):
        try:
            cursor = mysql.connection.cursor()
            cursor.execute("INSERT INTO Restaurant (name, location, image_url) VALUES (%s, %s, %s)", 
                           (name, location, image_url))
            mysql.connection.commit()
            cursor.close()
            return "Restaurant added successfully"
        except Exception as e:
            print("Error in Admin.add_restaurant:", e)
            return "Failed to add restaurant"

    @staticmethod
    def add_menu_item(restaurant_id, item_name, price, image_url):
        """ Adds a menu item with an image """
        connection = get_db_connection()
        if not connection:
            return "❌ Database Connection Failed"

        cursor = connection.cursor()
        try:
            cursor.execute("INSERT INTO Menu (restaurant_id, item_name, price, image_url) VALUES (%s, %s, %s, %s)", 
                           (restaurant_id, item_name, price, image_url))
            connection.commit()
            return "✅ Menu item added successfully!"
        except mysql.connector.Error as err:
            return f"❌ Error: {err}"
        finally:
            connection.close()

    @staticmethod
    def view_orders():
        """ Fetch all orders with user and restaurant info """
        connection = get_db_connection()
        if not connection:
            return "❌ Database Connection Failed"

        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT Orders.order_id, User.name AS customer_name, Restaurant.name AS restaurant_name, 
                   Orders.total_price AS amount, Orders.status, Orders.order_date
            FROM Orders
            JOIN User ON Orders.user_id = User.user_id
            JOIN Restaurant ON Orders.restaurant_id = Restaurant.restaurant_id
            ORDER BY Orders.order_date DESC
        """)
        orders = cursor.fetchall()
        connection.close()
        return orders  # Returns list of orders with details

# ✅ Admin: API to Add a Restaurant (POST)
@app.route('/admin/add_restaurant', methods=['POST'])
def api_add_restaurant():
    try:
        name = request.form.get('name')
        location = request.form.get('location')
        image = request.files.get('image')

        print("Received:", name, location, image)

        if not name or not location or not image:
            return jsonify({"error": "Missing required fields"}), 400

        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            print("Saving to:", image_path)
            image.save(image_path)
            image_url = url_for('static', filename=f'uploads/{filename}', _external=True)

            result = Admin.add_restaurant(name, location, image_url)
            print("DB Result:", result)
            return jsonify({"message": result, "image_url": image_url})
        else:
            return jsonify({"error": "Invalid image format"}), 400
    except Exception as e:
        print("Exception:", e)
        return jsonify({"error": "Server error", "details": str(e)}), 500

# ✅ Admin: API to Add a Menu Item (POST)
@app.route('/admin/add_menu_item', methods=['POST'])
def api_add_menu_item():
    restaurant_id = request.form.get('restaurant_id')
    item_name = request.form.get('item_name')
    price = request.form.get('price')
    image = request.files.get('image')

    if not restaurant_id or not item_name or not price or not image:
        return jsonify({"error": "Missing required fields"}), 400

    if image and allowed_file(image.filename):
        filename = secure_filename(image.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image.save(image_path)
        image_url = url_for('static', filename=f'uploads/{filename}', _external=True)

        result = Admin.add_menu_item(restaurant_id, item_name, price, image_url)
        return jsonify({"message": result, "image_url": image_url})
    else:
        return jsonify({"error": "Invalid image format"}), 400

# ✅ Admin: API to View Orders (GET)
@app.route('/admin/view_orders', methods=['GET'])
def api_view_orders():
    orders = Admin.view_orders()
    return jsonify(orders)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_id', None)
    session.pop('admin_name', None)
    flash("Logged out successfully", "success")
    return redirect(url_for('login'))  # Redirect to main user login page

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        password = generate_password_hash(request.form['password'])
        
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM User WHERE email = %s", (email,))
        if cursor.fetchone():
            flash("Email already registered!", "danger")
            return redirect(url_for('register'))
        
        cursor.execute("INSERT INTO User (name, email, phone, address, password) VALUES (%s, %s, %s, %s, %s)", 
                       (name, email, phone, address, password))
        connection.commit()
        connection.close()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM User WHERE email = %s", (email,))
        user = cursor.fetchone()
        connection.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['user_id']  # Store user ID in session
            session['username'] = user['name']    # Store username in session
            flash("Login successful!", "success")
            return redirect(url_for('restaurants'))
        else:
            flash("Invalid credentials!", "danger")
    
    return render_template('login.html')

@app.route('/restaurants')
def restaurants():
    if 'user_id' not in session:
        flash("Please log in to view restaurants", "warning")
        return redirect(url_for('login'))
        
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM Restaurant")
    restaurants = cursor.fetchall()
    connection.close()
    return render_template("restaurant.html", restaurants=restaurants)

@app.route('/restaurant/<int:restaurant_id>')
def get_restaurant(restaurant_id):
    if 'user' not in session:
        return jsonify({"error": "Unauthorized access"}), 401  # Prevent unauthorized users
    
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM Restaurant WHERE restaurant_id = %s", (restaurant_id,))
        restaurant = cursor.fetchone()
        connection.close()
        
        if not restaurant:
            return jsonify({"error": "Restaurant not found"}), 404
            
        return jsonify(restaurant)
    except mysql.connector.Error as err:
        return jsonify({"error": f"Database error: {err}"}), 500

@app.route('/menu/<int:restaurant_id>')
def get_menu(restaurant_id):
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM Menu WHERE restaurant_id = %s", (restaurant_id,))
        menu_items = cursor.fetchall()
        connection.close()
        return render_template("menu.html", menu_items=menu_items)
    except mysql.connector.Error as err:
        flash(f"Database error: {err}", "danger")
        return redirect(url_for('restaurants'))
    
@app.route('/menu/<int:restaurant_id>')
def menu(restaurant_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM Restaurants WHERE restaurant_id = %s", (restaurant_id,))
    restaurant = cursor.fetchone()
    conn.close()

    return render_template('menu.html', restaurant=restaurant)

@app.route('/api/user/address')
def get_user_address():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401

    connection = get_db_connection()
    cur = connection.cursor()
    cur.execute("SELECT name, address, phone FROM User WHERE user_id = %s", (user_id,))
    result = cur.fetchone()
    cur.close()
    connection.close()

    if result:
        name, address, phone = result
        return jsonify({
            'name': name,
            'address': address,
            'phone': phone
        })
    else:
        return jsonify({'error': 'User not found'}), 404


@app.route('/cart')
def cart():
    if 'user_id' not in session:
        flash("Please log in to view your cart", "warning")
        return redirect(url_for('login'))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        SELECT c.id, c.item_id, c.quantity, c.price,
               m.item_name, m.image_url
        FROM Cart c
        JOIN Menu m ON c.item_id = m.menu_id
        WHERE c.user_id = %s
    """, (session['user_id'],))
    
    cart_items = cursor.fetchall()
    connection.close()

    total_price = sum(item['price'] * item['quantity'] for item in cart_items)
    
    return render_template('cart.html', cart_items=cart_items, total_price=total_price)


@app.route("/add-to-cart", methods=["POST"])
def add_to_cart():
    if 'user_id' not in session:
        return jsonify({"error": "User not logged in"}), 401

    data = request.json
    item_id = data.get("item_id")
    quantity = int(data.get("quantity", 1))  # Default quantity is 1

    if not item_id or quantity < 1:
        return jsonify({"error": "Invalid item ID or quantity"}), 400

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Check if item already in cart
        cursor.execute("SELECT * FROM cart WHERE user_id = %s AND item_id = %s", 
                       (session['user_id'], item_id))
        existing_item = cursor.fetchone()

        if existing_item:
            # Update quantity
            new_quantity = existing_item["quantity"] + quantity
            cursor.execute("UPDATE cart SET quantity = %s WHERE user_id = %s AND item_id = %s", 
                           (new_quantity, session['user_id'], item_id))
        else:
            # Insert new item
            cursor.execute("SELECT name, price, image_url FROM menu WHERE id = %s", (item_id,))
            item = cursor.fetchone()

            if not item:
                return jsonify({"error": "Menu item not found"}), 404

            cursor.execute(
                "INSERT INTO cart (user_id, item_id, item_name, price, quantity, image_url) VALUES (%s, %s, %s, %s, %s, %s)",
                (session['user_id'], item_id, item['name'], item['price'], quantity, item['image_url'])
            )

        connection.commit()
        return jsonify({"message": "Item added to cart"}), 200

    except Exception as e:
        print("Error adding to cart:", str(e))
        return jsonify({"error": "Error adding to cart"}), 500

    finally:
        if connection:
            connection.close()

@app.route('/get-cart-items', methods=['GET'])
def get_cart_items():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
        
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        # Get all cart items with detailed information
        cursor.execute("""
            SELECT c.cart_id, c.item_id, c.quantity, c.price, 
                   m.item_name, m.image_url
            FROM Cart c
            JOIN Menu m ON c.item_id = m.menu_id
            WHERE c.user_id = %s
        """, (session['user_id'],))
        
        cart_items = cursor.fetchall()
        
        # Calculate total
        total = sum(item['price'] * item['quantity'] for item in cart_items)
        
        return jsonify({
            "items": cart_items,
            "total": total,
            "count": len(cart_items)
        })
        
    except Exception as e:
        print(f"Error getting cart: {str(e)}")
        return jsonify({"error": str(e)}), 500
        
    finally:
        if connection:
            connection.close()

@app.route('/update_cart', methods=['POST'])
@csrf.exempt  # If you need to exempt this route from CSRF protection
def update_cart():
    if 'user_id' not in session:
        return jsonify({"error": "User not logged in!"}), 401
    
    item_id = request.form.get('item_id')
    quantity = request.form.get('quantity')
    
    if not item_id or not quantity:
        return jsonify({"error": "Invalid request"}), 400
    
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        
        # Make sure the item belongs to the user's cart
        cursor.execute("UPDATE Cart SET quantity = %s WHERE item_id = %s AND user_id = %s",
                      (int(quantity), item_id, session['user_id']))
        
        connection.commit()
        return jsonify({"message": "Cart updated successfully"})
    
    except mysql.connector.Error as err:
        return jsonify({"error": f"Database error: {err}"}), 500
    
    finally:
        if connection:
            connection.close()

@app.route('/api/orders', methods=['GET'])
def get_user_orders():
    if 'user_id' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    try:
        user_id = session['user_id']
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT o.*, r.name as restaurant_name 
            FROM Orders o
            JOIN Restaurant r ON o.restaurant_id = r.restaurant_id
            WHERE o.user_id = %s
            ORDER BY o.order_date DESC
        """, (user_id,))
        
        orders = cursor.fetchall()
        connection.close()
        
        return jsonify({"orders": orders})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/order-status')
def order_status():
    if 'user_id' not in session:
        flash("Please log in to view your orders", "warning")
        return redirect(url_for('login'))

    try:
        user_id = session['user_id']
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT o.*, r.name as restaurant_name 
            FROM Orders o
            JOIN Restaurant r ON o.restaurant_id = r.restaurant_id
            WHERE o.user_id = %s
            ORDER BY o.order_date DESC
        """, (user_id,))
        
        orders = cursor.fetchall()
        connection.close()
        return render_template("order_status.html", orders=orders)
    
    except Exception as e:
        flash("Failed to load your orders. Please try again later.", "danger")
        return redirect(url_for('index'))

# Replace your current /order route with this improved version
@app.route('/order', methods=['POST'])
def place_order():

     # Debug: Show raw data and parsed JSON
    print("DEBUG RAW DATA:", request.data)
    data = request.get_json()
    print("DEBUG PARSED JSON:", data)

    # Now check if required keys are present
    if not data or 'user_id' not in data or 'items' not in data or 'address' not in data:
        return jsonify({'error': 'Missing required data'}), 400

    if 'user_id' not in session:
        return jsonify({"error": "User not logged in"}), 401
    
    connection = None
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        user_id = session['user_id']
        restaurant_id = data.get("restaurant_id")
        total_price = data.get("amount")
        
        # Debug information
        logging.info(f"Placing order: user_id={user_id}, restaurant_id={restaurant_id}, total_price={total_price}")
        
        # Validate parameters
        if not restaurant_id:
            return jsonify({"error": "Missing restaurant ID"}), 400
        if not total_price:
            return jsonify({"error": "Missing total price"}), 400
        
        connection = get_db_connection()
        if not connection:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = connection.cursor(dictionary=True)
        
        # Verify restaurant exists
        cursor.execute("SELECT restaurant_id FROM Restaurant WHERE restaurant_id = %s", (restaurant_id,))
        if not cursor.fetchone():
            return jsonify({"error": "Restaurant not found"}), 404
        
        # Create order - Make sure all fields match your Orders table structure
        try:
            cursor.execute("""
                INSERT INTO Orders (user_id, restaurant_id, total_price, status, order_date) 
                VALUES (%s, %s, %s, 'Pending', NOW())
            """, (user_id, restaurant_id, total_price))
            
            order_id = cursor.lastrowid
            connection.commit()
            
            # Clear the cart after successful order
            cursor.execute("DELETE FROM Cart WHERE user_id = %s", (user_id,))
            connection.commit()
            
            return jsonify({
                "success": True,
                "message": "Order placed successfully", 
                "order_id": order_id
            })
        except mysql.connector.Error as db_err:
            logging.error(f"SQL error in order placement: {str(db_err)}")
            return jsonify({"error": f"Database error: {str(db_err)}"}), 500
            
    except Exception as e:
        logging.error(f"Error placing order: {str(e)}")
        return jsonify({"error": "Failed to place order. Please try again."}), 500
    
    finally:
        if connection:
            connection.close()

@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    data = request.json
    amount = int(data['amount']) * 100  # Convert to cents (smallest currency unit)

    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'inr',
                    'product_data': {'name': 'FoodExpress Order'},
                    'unit_amount': amount,
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url='http://127.0.0.1:5000/success',
            cancel_url='http://127.0.0.1:5000/cancel',
        )
        return jsonify({'id': session.id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# Payment Route
@app.route('/payment', methods=['POST'])
def process_payment():
    if 'user_id' not in session:
        return jsonify({"error": "User not logged in"}), 401

    data = request.json
    if not data:
        return jsonify({"error": "No payment data provided"}), 400
        
    user_id = session['user_id']
    order_id = data.get("order_id")
    payment_method = data.get("payment_method")
    amount = data.get("amount")

    # Validate parameters
    if not order_id or not payment_method or not amount:
        return jsonify({"error": "Missing required payment information"}), 400

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Verify order exists for the user
        cursor.execute("SELECT * FROM Orders WHERE order_id = %s AND user_id = %s", 
                      (order_id, user_id))
        order = cursor.fetchone()

        if not order:
            return jsonify({"error": "Invalid order"}), 404

        # Generate transaction ID for non-COD payments
        transaction_id = None
        if payment_method != 'Cash on Delivery':
            transaction_id = ''.join(random.choices(
                string.ascii_uppercase + string.digits, k=12))

        # Insert Payment Record
        cursor.execute("""
            INSERT INTO Payment (order_id, user_id, payment_method, amount, status, transaction_id)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (order_id, user_id, payment_method, amount, 'Success', transaction_id))

        # Update Order Status
        cursor.execute("UPDATE Orders SET status = 'Confirmed' WHERE order_id = %s", 
                      (order_id,))
        connection.commit()
        connection.close()

        return jsonify({
            "success": True,
            "message": "Payment processed successfully",
            "order_id": order_id,
            "transaction_id": transaction_id
        })
        
    except Exception as e:
        logging.error(f"Error processing payment: {str(e)}")
        return jsonify({"error": "Payment failed. Please try again."}), 500

@app.route('/payment-page', methods=['GET'])
def payment_page():
    if 'user_id' not in session:
        return redirect('/login')
    
    user_id = session['user_id']
    order_id = request.args.get('order_id')
    
    if not order_id:
        return redirect('/orders')
    
    connection = get_db_connection()
    cursor = connection.cursor()
    
    # Verify order exists for the user
    cursor.execute("SELECT * FROM Orders WHERE order_id = %s AND user_id = %s", (order_id, user_id))
    order = cursor.fetchone()
    
    cursor.execute("SELECT * FROM OrderDetails WHERE order_id = %s", (order_id,))
    order_details = cursor.fetchone()  # Fetch only one record
    
    # Debugging
    print("Order Details Debug:", order_details)  # <-- ADD THIS LINE HERE
    
    if not order:
        print("Error: No order found for order_id:", order_id, "and user_id:", user_id)
        
    if not order_details:
        print("Error: No order details found for order_id:", order_id)

    # Render the payment template with necessary data
    return render_template('payment.html', 
                          order=order, 
                          order_details=order_details)

@app.route('/payment', methods=['POST'])
def handle_payment():
    data = request.get_json()
    order_id = data.get('order_id')
    payment_method = data.get('payment_method')
    amount = data.get('amount')

    if not order_id or not payment_method or not amount:
        return jsonify({'error': 'Missing payment information'}), 400

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO Payment (order_id, payment_method, amount, status)
            VALUES (%s, %s, %s, %s)
        """, (order_id, payment_method, amount, 'Success'))

        cursor.execute("""
            UPDATE Orders SET status = 'Confirmed' WHERE order_id = %s
        """, (order_id,))

        connection.commit()
        cursor.close()
        connection.close()

        return jsonify({'success': True, 'message': 'Payment processed successfully'})
    except Exception as e:
        print("Payment error:", e)
        return jsonify({'error': 'Payment failed'}), 500

@app.route('/logout')
def logout():
    if 'user_id' in session:  # Check if user is logged in
        session.clear()  # Clear session data
        flash("You have been logged out successfully", "success")
        return redirect(url_for('login'))
    else:
        flash("Unauthorized access! Please log in first.", "danger")
        return redirect(url_for('login'))
    
if __name__ == "__main__":
    app.run(debug=True, port=5000)
