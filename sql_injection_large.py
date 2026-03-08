import sqlite3
import logging
import psycopg2
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

# Database connection variable
db_connection = None


# ============================================================
# ENTITY: users
# Operations: select_by_id, search, select_filtered, update,
#             delete, insert, select_join, select_multi
# 3 variants each (f-string, concatenation, % formatting)
# ============================================================

# --- select_by_id ---

@app.route("/vulnerable/user/select_by_id/0")
def vuln_user_select_by_id_v0():
    """Vulnerable user lookup by ID - variant 0"""
    param = request.args.get("id", "")
    query = f"SELECT id, username, email, password, role, status FROM users WHERE id = {param}"
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_select_by_id_v0: {e}")
        return Response("Database error", status=500)


@app.route("/vulnerable/user/select_by_id/1")
def vuln_user_select_by_id_v1():
    """Vulnerable user lookup by ID - variant 1"""
    param = request.args.get("id", "")
    query = "SELECT id, username, email, password, role, status FROM users WHERE id = " + param
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_select_by_id_v1: {e}")
        return Response("Database error", status=500)


@app.route("/vulnerable/user/select_by_id/2")
def vuln_user_select_by_id_v2():
    """Vulnerable user lookup by ID - variant 2"""
    param = request.args.get("id", "")
    query = "SELECT id, username, email, password, role, status FROM users WHERE id = %s" % param
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_select_by_id_v2: {e}")
        return Response("Database error", status=500)


# --- search ---

@app.route("/vulnerable/user/search/0")
def vuln_user_search_v0():
    """Vulnerable user search - variant 0"""
    term = request.args.get("q", "")
    query = f"SELECT id, username, email, password, role, status FROM users WHERE username LIKE '%{term}%'"
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_search_v0: {e}")
        return Response("Database error", status=500)


@app.route("/vulnerable/user/search/1")
def vuln_user_search_v1():
    """Vulnerable user search - variant 1"""
    term = request.args.get("q", "")
    query = "SELECT id, username, email, password, role, status FROM users WHERE username LIKE '%" + term + "%'"
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_search_v1: {e}")
        return Response("Database error", status=500)


@app.route("/vulnerable/user/search/2")
def vuln_user_search_v2():
    """Vulnerable user search - variant 2"""
    term = request.args.get("q", "")
    query = "SELECT id, username, email, password, role, status FROM users WHERE username LIKE '%%%s%%'" % term
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_search_v2: {e}")
        return Response("Database error", status=500)


# --- select_filtered ---

@app.route("/vulnerable/user/select_filtered/0")
def vuln_user_select_filtered_v0():
    """Vulnerable user filtered select - variant 0"""
    filter_val = request.args.get("filter", "")
    sort_by = request.args.get("sort", "id")
    query = f"SELECT id, username, email, password, role, status FROM users WHERE password = '{filter_val}' ORDER BY {sort_by}"
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_select_filtered_v0: {e}")
        return Response("Database error", status=500)


@app.route("/vulnerable/user/select_filtered/1")
def vuln_user_select_filtered_v1():
    """Vulnerable user filtered select - variant 1"""
    filter_val = request.args.get("filter", "")
    sort_by = request.args.get("sort", "id")
    query = "SELECT id, username, email, password, role, status FROM users WHERE password = '" + filter_val + "' ORDER BY " + sort_by
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_select_filtered_v1: {e}")
        return Response("Database error", status=500)


@app.route("/vulnerable/user/select_filtered/2")
def vuln_user_select_filtered_v2():
    """Vulnerable user filtered select - variant 2"""
    filter_val = request.args.get("filter", "")
    sort_by = request.args.get("sort", "id")
    query = "SELECT id, username, email, password, role, status FROM users WHERE password = '%s' ORDER BY %s" % (filter_val, sort_by)
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_select_filtered_v2: {e}")
        return Response("Database error", status=500)


# --- update ---

@app.route("/vulnerable/user/update/0", methods=["POST"])
def vuln_user_update_v0():
    """Vulnerable user update - variant 0"""
    record_id = request.form.get("id", "")
    new_value = request.form.get("value", "")
    query = f"UPDATE users SET email = '{new_value}' WHERE id = {record_id}"
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        db_connection.commit()
        return Response("Operation successful", mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_update_v0: {e}")
        return Response("Database error", status=500)


@app.route("/vulnerable/user/update/1", methods=["POST"])
def vuln_user_update_v1():
    """Vulnerable user update - variant 1"""
    record_id = request.form.get("id", "")
    new_value = request.form.get("value", "")
    query = "UPDATE users SET email = '" + new_value + "' WHERE id = " + record_id
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        db_connection.commit()
        return Response("Operation successful", mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_update_v1: {e}")
        return Response("Database error", status=500)


@app.route("/vulnerable/user/update/2", methods=["POST"])
def vuln_user_update_v2():
    """Vulnerable user update - variant 2"""
    record_id = request.form.get("id", "")
    new_value = request.form.get("value", "")
    query = "UPDATE users SET email = '%s' WHERE id = %s" % (new_value, record_id)
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        db_connection.commit()
        return Response("Operation successful", mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_update_v2: {e}")
        return Response("Database error", status=500)


# --- delete ---

@app.route("/vulnerable/user/delete/0", methods=["POST"])
def vuln_user_delete_v0():
    """Vulnerable user delete - variant 0"""
    record_id = request.form.get("id", "")
    query = f"DELETE FROM users WHERE id = {record_id}"
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        db_connection.commit()
        return Response("Operation successful", mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_delete_v0: {e}")
        return Response("Database error", status=500)


@app.route("/vulnerable/user/delete/1", methods=["POST"])
def vuln_user_delete_v1():
    """Vulnerable user delete - variant 1"""
    record_id = request.form.get("id", "")
    query = "DELETE FROM users WHERE id = " + record_id
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        db_connection.commit()
        return Response("Operation successful", mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_delete_v1: {e}")
        return Response("Database error", status=500)


@app.route("/vulnerable/user/delete/2", methods=["POST"])
def vuln_user_delete_v2():
    """Vulnerable user delete - variant 2"""
    record_id = request.form.get("id", "")
    query = "DELETE FROM users WHERE id = %s" % record_id
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        db_connection.commit()
        return Response("Operation successful", mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_delete_v2: {e}")
        return Response("Database error", status=500)


# --- insert ---

@app.route("/vulnerable/user/insert/0", methods=["POST"])
def vuln_user_insert_v0():
    """Vulnerable user insert - variant 0"""
    username_val = request.form.get("username", "")
    email_val = request.form.get("email", "")
    password_val = request.form.get("password", "")
    query = f"INSERT INTO users (username, email, password) VALUES ('{username_val}', '{email_val}', '{password_val}')"
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        db_connection.commit()
        return Response("Operation successful", mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_insert_v0: {e}")
        return Response("Database error", status=500)


@app.route("/vulnerable/user/insert/1", methods=["POST"])
def vuln_user_insert_v1():
    """Vulnerable user insert - variant 1"""
    username_val = request.form.get("username", "")
    email_val = request.form.get("email", "")
    password_val = request.form.get("password", "")
    query = "INSERT INTO users (username, email, password) VALUES ('" + username_val + "', '" + email_val + "', '" + password_val + "')"
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        db_connection.commit()
        return Response("Operation successful", mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_insert_v1: {e}")
        return Response("Database error", status=500)


@app.route("/vulnerable/user/insert/2", methods=["POST"])
def vuln_user_insert_v2():
    """Vulnerable user insert - variant 2"""
    username_val = request.form.get("username", "")
    email_val = request.form.get("email", "")
    password_val = request.form.get("password", "")
    query = "INSERT INTO users (username, email, password) VALUES ('%s', '%s', '%s')" % (username_val, email_val, password_val)
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        db_connection.commit()
        return Response("Operation successful", mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_insert_v2: {e}")
        return Response("Database error", status=500)


# --- select_join ---

@app.route("/vulnerable/user/select_join/0")
def vuln_user_select_join_v0():
    """Vulnerable user join query - variant 0"""
    param = request.args.get("id", "")
    query = f"SELECT t1.*, t2.* FROM users t1 JOIN orders t2 ON t1.id = t2.user_id WHERE t1.id = {param}"
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_select_join_v0: {e}")
        return Response("Database error", status=500)


@app.route("/vulnerable/user/select_join/1")
def vuln_user_select_join_v1():
    """Vulnerable user join query - variant 1"""
    param = request.args.get("id", "")
    query = "SELECT t1.*, t2.* FROM users t1 JOIN orders t2 ON t1.id = t2.user_id WHERE t1.id = " + param
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_select_join_v1: {e}")
        return Response("Database error", status=500)


@app.route("/vulnerable/user/select_join/2")
def vuln_user_select_join_v2():
    """Vulnerable user join query - variant 2"""
    param = request.args.get("id", "")
    query = "SELECT t1.*, t2.* FROM users t1 JOIN orders t2 ON t1.id = t2.user_id WHERE t1.id = %s" % param
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_select_join_v2: {e}")
        return Response("Database error", status=500)


# --- select_multi ---

@app.route("/vulnerable/user/select_multi/0")
def vuln_user_select_multi_v0():
    """Vulnerable user multi-condition query - variant 0"""
    param1 = request.args.get("p1", "")
    param2 = request.args.get("p2", "")
    limit_val = request.args.get("limit", "10")
    query = f"SELECT id, username, email, password, role, status FROM users WHERE username = '{param1}' AND password = '{param2}' LIMIT {limit_val}"
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_select_multi_v0: {e}")
        return Response("Database error", status=500)


@app.route("/vulnerable/user/select_multi/1")
def vuln_user_select_multi_v1():
    """Vulnerable user multi-condition query - variant 1"""
    param1 = request.args.get("p1", "")
    param2 = request.args.get("p2", "")
    limit_val = request.args.get("limit", "10")
    query = "SELECT id, username, email, password, role, status FROM users WHERE username = '" + param1 + "' AND password = '" + param2 + "' LIMIT " + limit_val
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_select_multi_v1: {e}")
        return Response("Database error", status=500)


@app.route("/vulnerable/user/select_multi/2")
def vuln_user_select_multi_v2():
    """Vulnerable user multi-condition query - variant 2"""
    param1 = request.args.get("p1", "")
    param2 = request.args.get("p2", "")
    limit_val = request.args.get("limit", "10")
    query = "SELECT id, username, email, password, role, status FROM users WHERE username = '%s' AND password = '%s' LIMIT %s" % (param1, param2, limit_val)
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_user_select_multi_v2: {e}")
        return Response("Database error", status=500)


# ============================================================
# ENTITY: products (only single-param operations to stay under 50)
# ============================================================

# --- select_by_id ---

@app.route("/vulnerable/product/select_by_id/0")
def vuln_product_select_by_id_v0():
    """Vulnerable product lookup by ID - variant 0"""
    param = request.args.get("id", "")
    query = f"SELECT id, name, price, description, category, stock FROM products WHERE id = {param}"
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_product_select_by_id_v0: {e}")
        return Response("Database error", status=500)


@app.route("/vulnerable/product/select_by_id/1")
def vuln_product_select_by_id_v1():
    """Vulnerable product lookup by ID - variant 1"""
    param = request.args.get("id", "")
    query = "SELECT id, name, price, description, category, stock FROM products WHERE id = " + param
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_product_select_by_id_v1: {e}")
        return Response("Database error", status=500)


@app.route("/vulnerable/product/select_by_id/2")
def vuln_product_select_by_id_v2():
    """Vulnerable product lookup by ID - variant 2"""
    param = request.args.get("id", "")
    query = "SELECT id, name, price, description, category, stock FROM products WHERE id = %s" % param
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_product_select_by_id_v2: {e}")
        return Response("Database error", status=500)


# --- search ---

@app.route("/vulnerable/product/search/0")
def vuln_product_search_v0():
    """Vulnerable product search - variant 0"""
    term = request.args.get("q", "")
    query = f"SELECT id, name, price, description, category, stock FROM products WHERE name LIKE '%{term}%'"
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_product_search_v0: {e}")
        return Response("Database error", status=500)


@app.route("/vulnerable/product/search/1")
def vuln_product_search_v1():
    """Vulnerable product search - variant 1"""
    term = request.args.get("q", "")
    query = "SELECT id, name, price, description, category, stock FROM products WHERE name LIKE '%" + term + "%'"
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_product_search_v1: {e}")
        return Response("Database error", status=500)


@app.route("/vulnerable/product/search/2")
def vuln_product_search_v2():
    """Vulnerable product search - variant 2"""
    term = request.args.get("q", "")
    query = "SELECT id, name, price, description, category, stock FROM products WHERE name LIKE '%%%s%%'" % term
    logging.info(f"Executing: {query}")
    try:
        cursor = db_connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        result = [str(row) for row in rows]
        return Response("\n".join(result), mimetype="text/plain")
    except Exception as e:
        logging.error(f"Query error in vuln_product_search_v2: {e}")
        return Response("Database error", status=500)


def init_db():
    """Initialize database connection"""
    global db_connection
    try:
        db_connection = sqlite3.connect(":memory:", check_same_thread=False)
        print("Database initialized")
    except Exception as e:
        logging.error(f"DB connection error: {e}")


if __name__ == "__main__":
    init_db()
    print("Starting server with 30 vulnerable endpoints...")
    app.run(host="0.0.0.0", port=8080, debug=True)
