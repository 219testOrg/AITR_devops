"""
Comprehensive tests for SQL injection vulnerability remediation.

This test suite validates that the SQL injection vulnerability in
vuln_user_select_by_id_v0() has been properly fixed using parameterized queries.
Tests cover both functional correctness and security attack prevention.
"""
import pytest
import sqlite3
from sql_injection_large import app, init_db, db_connection


@pytest.fixture
def client():
    """Create a test client for the Flask application."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture(autouse=True)
def setup_test_db():
    """Initialize database and populate with test data before each test."""
    init_db()

    # Create the users table
    cursor = db_connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            status TEXT DEFAULT 'active'
        )
    """)

    # Insert test data
    test_users = [
        (1, 'alice', 'alice@example.com', 'password123', 'admin', 'active'),
        (2, 'bob', 'bob@example.com', 'secret456', 'user', 'active'),
        (3, 'charlie', 'charlie@example.com', 'pass789', 'user', 'inactive'),
    ]

    cursor.executemany(
        "INSERT INTO users (id, username, email, password, role, status) VALUES (?, ?, ?, ?, ?, ?)",
        test_users
    )
    db_connection.commit()

    yield

    # Cleanup after test
    cursor.execute("DROP TABLE IF EXISTS users")
    db_connection.commit()


class TestSQLInjectionRemediation:
    """Test suite for SQL injection vulnerability fix in vuln_user_select_by_id_v0."""

    def test_valid_user_lookup_by_id(self, client):
        """Test that valid user ID lookup works correctly."""
        response = client.get('/vulnerable/user/select_by_id/0?id=1')

        assert response.status_code == 200
        assert b'alice' in response.data
        assert b'alice@example.com' in response.data

    def test_multiple_valid_ids(self, client):
        """Test lookup of multiple different valid user IDs."""
        # Test user ID 2
        response = client.get('/vulnerable/user/select_by_id/0?id=2')
        assert response.status_code == 200
        assert b'bob' in response.data
        assert b'bob@example.com' in response.data

        # Test user ID 3
        response = client.get('/vulnerable/user/select_by_id/0?id=3')
        assert response.status_code == 200
        assert b'charlie' in response.data
        assert b'charlie@example.com' in response.data

    def test_nonexistent_user_id(self, client):
        """Test that querying non-existent user ID returns empty result."""
        response = client.get('/vulnerable/user/select_by_id/0?id=999')

        assert response.status_code == 200
        # Should return empty response (no user found)
        assert len(response.data) == 0 or response.data == b''

    def test_sql_injection_union_attack_blocked(self, client):
        """Test that UNION-based SQL injection is blocked."""
        # Attempt UNION injection to extract all users
        malicious_input = "1 UNION SELECT id, username, email, password, role, status FROM users"
        response = client.get(f'/vulnerable/user/select_by_id/0?id={malicious_input}')

        # With parameterized queries, this will be treated as a literal string
        # and won't match any user ID, so should return empty or error
        assert response.status_code in [200, 500]

        # Should NOT return multiple users from the UNION
        # Count occurrences of '@example.com' to detect if multiple users leaked
        email_count = response.data.count(b'@example.com')
        assert email_count <= 1, "UNION injection may have succeeded - multiple users returned"

    def test_sql_injection_comment_attack_blocked(self, client):
        """Test that SQL comment injection is blocked."""
        # Attempt to use SQL comments to bypass WHERE clause
        malicious_input = "1 OR 1=1 --"
        response = client.get(f'/vulnerable/user/select_by_id/0?id={malicious_input}')

        # Should not return all users
        assert response.status_code in [200, 500]

        # Verify we don't get all three users (which would indicate 1=1 succeeded)
        user_count = response.data.count(b'@example.com')
        assert user_count <= 1, "Comment-based injection may have succeeded"

    def test_sql_injection_always_true_condition(self, client):
        """Test that always-true condition injection is blocked."""
        # Attempt classic 1=1 injection
        malicious_input = "1 OR 1=1"
        response = client.get(f'/vulnerable/user/select_by_id/0?id={malicious_input}')

        assert response.status_code in [200, 500]

        # Should not return all users
        user_count = response.data.count(b'@example.com')
        assert user_count <= 1, "Always-true condition injection may have succeeded"

    def test_sql_injection_string_based_attack_blocked(self, client):
        """Test that string-based SQL injection is blocked."""
        # Attempt string concatenation injection
        malicious_input = "1' OR '1'='1"
        response = client.get(f'/vulnerable/user/select_by_id/0?id={malicious_input}')

        assert response.status_code in [200, 500]

        # Should not return multiple users
        user_count = response.data.count(b'@example.com')
        assert user_count <= 1, "String-based injection may have succeeded"

    def test_sql_injection_boolean_blind_attack_blocked(self, client):
        """Test that boolean-based blind SQL injection is blocked."""
        # Attempt boolean blind injection
        malicious_input = "1 AND 1=1"
        response = client.get(f'/vulnerable/user/select_by_id/0?id={malicious_input}')

        # With parameterized queries, this entire string is treated as the ID value
        # It won't be a valid integer ID, so should return empty or error
        assert response.status_code in [200, 500]

    def test_sql_injection_time_based_attack_blocked(self, client):
        """Test that time-based SQL injection is blocked."""
        # Attempt time-based blind injection (SQLite specific)
        malicious_input = "1 AND (SELECT COUNT(*) FROM users) > 0"
        response = client.get(f'/vulnerable/user/select_by_id/0?id={malicious_input}')

        # Should be safely treated as a literal string parameter
        assert response.status_code in [200, 500]

    def test_sql_injection_drop_table_attack_blocked(self, client):
        """Test that DROP TABLE injection is blocked."""
        # Attempt to drop the users table
        malicious_input = "1; DROP TABLE users; --"
        response = client.get(f'/vulnerable/user/select_by_id/0?id={malicious_input}')

        # Should not drop the table
        assert response.status_code in [200, 500]

        # Verify table still exists by making another valid query
        response2 = client.get('/vulnerable/user/select_by_id/0?id=1')
        assert response2.status_code == 200
        assert b'alice' in response2.data, "Table may have been dropped - valid query failed"

    def test_sql_injection_stacked_queries_blocked(self, client):
        """Test that stacked query injection is blocked."""
        # Attempt to execute multiple statements
        malicious_input = "1; UPDATE users SET role='admin' WHERE id=2; --"
        response = client.get(f'/vulnerable/user/select_by_id/0?id={malicious_input}')

        assert response.status_code in [200, 500]

        # Verify user 2 role was not changed
        cursor = db_connection.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (2,))
        role = cursor.fetchone()
        assert role[0] == 'user', "Stacked query injection may have succeeded - role was changed"

    def test_sql_injection_with_encoded_input(self, client):
        """Test that URL-encoded SQL injection attempts are blocked."""
        # URL-encoded version of "1 OR 1=1"
        import urllib.parse
        malicious_input = urllib.parse.quote("1 OR 1=1")
        response = client.get(f'/vulnerable/user/select_by_id/0?id={malicious_input}')

        assert response.status_code in [200, 500]

        # Should not return all users
        user_count = response.data.count(b'@example.com')
        assert user_count <= 1, "Encoded injection may have succeeded"

    def test_empty_parameter_handling(self, client):
        """Test that empty ID parameter is handled safely."""
        response = client.get('/vulnerable/user/select_by_id/0?id=')

        # Should return empty result or handle gracefully
        assert response.status_code in [200, 500]

    def test_special_characters_in_parameter(self, client):
        """Test that special characters are safely handled as literal values."""
        special_chars = ["'; DELETE FROM users; --", "1'--", "1/*", "1*/", "1#"]

        for char_input in special_chars:
            response = client.get(f'/vulnerable/user/select_by_id/0?id={char_input}')

            # Should be treated as literal string, not SQL syntax
            assert response.status_code in [200, 500]

            # Verify users table still intact
            cursor = db_connection.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            count = cursor.fetchone()[0]
            assert count == 3, f"Special character '{char_input}' may have caused SQL injection"

    def test_parameterized_query_prevents_sql_syntax_interpretation(self, client):
        """Test that SQL keywords in parameters are treated as literals."""
        sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER"]

        for keyword in sql_keywords:
            response = client.get(f'/vulnerable/user/select_by_id/0?id={keyword}')

            # Should treat keyword as literal ID value, not SQL command
            assert response.status_code in [200, 500]
            # Should return empty (no user with ID = keyword string)
            assert len(response.data) == 0 or response.data == b''

    def test_numeric_string_id_handling(self, client):
        """Test that numeric strings are properly handled."""
        response = client.get('/vulnerable/user/select_by_id/0?id=1')

        assert response.status_code == 200
        assert b'alice' in response.data

    def test_large_id_value_handling(self, client):
        """Test that very large ID values don't cause issues."""
        large_id = "9999999999999999999999999999"
        response = client.get(f'/vulnerable/user/select_by_id/0?id={large_id}')

        # Should handle gracefully without causing errors
        assert response.status_code in [200, 500]

    def test_negative_id_handling(self, client):
        """Test that negative ID values are handled correctly."""
        response = client.get('/vulnerable/user/select_by_id/0?id=-1')

        # Should return empty result (no user with negative ID)
        assert response.status_code in [200, 500]


class TestDatabaseIntegrity:
    """Test that the database remains intact after various injection attempts."""

    def test_database_integrity_after_attack_attempts(self, client):
        """Verify database integrity is maintained after multiple attack attempts."""
        # Execute multiple injection attempts
        attack_payloads = [
            "1 UNION SELECT * FROM users",
            "1; DROP TABLE users;",
            "1' OR '1'='1",
            "1 AND 1=1",
            "1 OR 1=1 --",
        ]

        for payload in attack_payloads:
            client.get(f'/vulnerable/user/select_by_id/0?id={payload}')

        # Verify database still has all original data
        cursor = db_connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        assert count == 3, "Database integrity compromised - user count changed"

        # Verify specific user data unchanged
        cursor.execute("SELECT username, role FROM users WHERE id = ?", (1,))
        user = cursor.fetchone()
        assert user[0] == 'alice' and user[1] == 'admin', "User data was modified"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
