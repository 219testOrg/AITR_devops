"""
Comprehensive security tests for the remediated code injection vulnerability in sast_critical_high.py

This test suite validates that:
1. The /calc endpoint correctly evaluates safe mathematical expressions
2. Malicious code injection attempts are blocked
3. The fix prevents regression of the CWE-94 vulnerability
4. Edge cases and attack vectors are properly handled
"""

import pytest
from sast_critical_high import app, safe_eval_expr, _eval_node, SAFE_OPERATORS


@pytest.fixture
def client():
    """Create a Flask test client for the application."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


class TestSafeEvalExpr:
    """Test suite for the safe_eval_expr function that replaces eval()"""

    # ========================================================================
    # POSITIVE TEST CASES - Valid mathematical expressions
    # ========================================================================

    def test_simple_addition(self):
        """Test basic addition operation"""
        result = safe_eval_expr("2 + 3")
        assert result == 5

    def test_simple_subtraction(self):
        """Test basic subtraction operation"""
        result = safe_eval_expr("10 - 3")
        assert result == 7

    def test_simple_multiplication(self):
        """Test basic multiplication operation"""
        result = safe_eval_expr("4 * 5")
        assert result == 20

    def test_simple_division(self):
        """Test basic division operation"""
        result = safe_eval_expr("20 / 4")
        assert result == 5.0

    def test_floor_division(self):
        """Test floor division operation"""
        result = safe_eval_expr("7 // 2")
        assert result == 3

    def test_modulo_operation(self):
        """Test modulo operation"""
        result = safe_eval_expr("10 % 3")
        assert result == 1

    def test_power_operation(self):
        """Test exponentiation operation"""
        result = safe_eval_expr("2 ** 3")
        assert result == 8

    def test_unary_negative(self):
        """Test unary negative operator"""
        result = safe_eval_expr("-5")
        assert result == -5

    def test_unary_positive(self):
        """Test unary positive operator"""
        result = safe_eval_expr("+5")
        assert result == 5

    def test_complex_expression(self):
        """Test complex mathematical expression with multiple operators"""
        result = safe_eval_expr("2 + 3 * 4")
        assert result == 14  # Should follow order of operations

    def test_expression_with_parentheses(self):
        """Test expression with parentheses for precedence"""
        result = safe_eval_expr("(2 + 3) * 4")
        assert result == 20

    def test_nested_expression(self):
        """Test deeply nested mathematical expression"""
        result = safe_eval_expr("((2 + 3) * (4 - 1)) / 3")
        assert result == 5.0

    def test_float_numbers(self):
        """Test expressions with floating point numbers"""
        result = safe_eval_expr("3.5 + 2.5")
        assert result == 6.0

    def test_negative_numbers_in_expression(self):
        """Test expressions with negative numbers"""
        result = safe_eval_expr("-5 + 10")
        assert result == 5

    # ========================================================================
    # NEGATIVE TEST CASES - Code injection attempts (SECURITY CRITICAL)
    # ========================================================================

    def test_blocks_import_statement(self):
        """Test that import statements are blocked (code injection attack)"""
        with pytest.raises(ValueError):
            safe_eval_expr("__import__('os').system('ls')")

    def test_blocks_exec_function(self):
        """Test that exec() function calls are blocked"""
        with pytest.raises(ValueError):
            safe_eval_expr("exec('print(1)')")

    def test_blocks_eval_function(self):
        """Test that nested eval() calls are blocked"""
        with pytest.raises(ValueError):
            safe_eval_expr("eval('1+1')")

    def test_blocks_open_function(self):
        """Test that file operations are blocked"""
        with pytest.raises(ValueError):
            safe_eval_expr("open('/etc/passwd').read()")

    def test_blocks_lambda_expressions(self):
        """Test that lambda expressions are blocked"""
        with pytest.raises(ValueError):
            safe_eval_expr("(lambda x: x + 1)(5)")

    def test_blocks_list_comprehension(self):
        """Test that list comprehensions are blocked"""
        with pytest.raises(ValueError):
            safe_eval_expr("[x for x in range(10)]")

    def test_blocks_function_calls(self):
        """Test that function calls are blocked"""
        with pytest.raises(ValueError):
            safe_eval_expr("print(1)")

    def test_blocks_attribute_access(self):
        """Test that attribute access is blocked (e.g., __builtins__)"""
        with pytest.raises(ValueError):
            safe_eval_expr("().__class__.__bases__[0].__subclasses__()")

    def test_blocks_variable_names(self):
        """Test that variable names are blocked"""
        with pytest.raises(ValueError):
            safe_eval_expr("os.system('ls')")

    def test_blocks_globals_access(self):
        """Test that globals() access is blocked"""
        with pytest.raises(ValueError):
            safe_eval_expr("globals()")

    def test_blocks_locals_access(self):
        """Test that locals() access is blocked"""
        with pytest.raises(ValueError):
            safe_eval_expr("locals()")

    def test_blocks_string_literals(self):
        """Test that string literals are blocked (only numbers allowed)"""
        with pytest.raises(ValueError):
            safe_eval_expr("'malicious string'")

    def test_blocks_boolean_operators(self):
        """Test that boolean operators (and, or, not) are blocked"""
        with pytest.raises(ValueError):
            safe_eval_expr("True and False")

    def test_blocks_comparison_operators(self):
        """Test that comparison operators are blocked"""
        with pytest.raises(ValueError):
            safe_eval_expr("1 > 2")

    def test_blocks_bitwise_operators(self):
        """Test that bitwise operators are blocked"""
        with pytest.raises(ValueError):
            safe_eval_expr("5 & 3")

    # ========================================================================
    # EDGE CASES
    # ========================================================================

    def test_empty_expression(self):
        """Test handling of empty expression"""
        with pytest.raises(ValueError):
            safe_eval_expr("")

    def test_division_by_zero(self):
        """Test handling of division by zero"""
        with pytest.raises(ValueError):
            safe_eval_expr("1 / 0")

    def test_invalid_syntax(self):
        """Test handling of invalid syntax"""
        with pytest.raises(ValueError):
            safe_eval_expr("2 + + 3")

    def test_incomplete_expression(self):
        """Test handling of incomplete expression"""
        with pytest.raises(ValueError):
            safe_eval_expr("2 +")

    def test_single_number(self):
        """Test single number as valid expression"""
        result = safe_eval_expr("42")
        assert result == 42

    def test_zero_value(self):
        """Test zero as valid expression"""
        result = safe_eval_expr("0")
        assert result == 0


class TestCalculatorEndpoint:
    """Test suite for the /calc HTTP endpoint"""

    # ========================================================================
    # POSITIVE TEST CASES - Valid requests
    # ========================================================================

    def test_calc_endpoint_simple_addition(self, client):
        """Test /calc endpoint with simple addition"""
        response = client.get('/calc?expr=2+3')
        assert response.status_code == 200
        assert response.data.decode() == '5'
        assert response.mimetype == 'text/plain'

    def test_calc_endpoint_multiplication(self, client):
        """Test /calc endpoint with multiplication"""
        response = client.get('/calc?expr=4*5')
        assert response.status_code == 200
        assert response.data.decode() == '20'

    def test_calc_endpoint_complex_expression(self, client):
        """Test /calc endpoint with complex expression"""
        response = client.get('/calc?expr=(10+5)*2')
        assert response.status_code == 200
        assert response.data.decode() == '30'

    def test_calc_endpoint_default_value(self, client):
        """Test /calc endpoint without expr parameter (should default to 0)"""
        response = client.get('/calc')
        assert response.status_code == 200
        assert response.data.decode() == '0'

    def test_calc_endpoint_negative_result(self, client):
        """Test /calc endpoint with negative result"""
        response = client.get('/calc?expr=5-10')
        assert response.status_code == 200
        assert response.data.decode() == '-5'

    def test_calc_endpoint_float_result(self, client):
        """Test /calc endpoint with float result"""
        response = client.get('/calc?expr=7/2')
        assert response.status_code == 200
        assert response.data.decode() == '3.5'

    # ========================================================================
    # SECURITY TEST CASES - Attack prevention
    # ========================================================================

    def test_calc_endpoint_blocks_os_system(self, client):
        """Test that /calc endpoint blocks os.system() injection"""
        response = client.get('/calc?expr=__import__("os").system("ls")')
        assert response.status_code == 400
        assert 'Error' in response.data.decode()

    def test_calc_endpoint_blocks_exec(self, client):
        """Test that /calc endpoint blocks exec() injection"""
        response = client.get('/calc?expr=exec("import os")')
        assert response.status_code == 400
        assert 'Error' in response.data.decode()

    def test_calc_endpoint_blocks_eval(self, client):
        """Test that /calc endpoint blocks nested eval() injection"""
        response = client.get('/calc?expr=eval("1+1")')
        assert response.status_code == 400
        assert 'Error' in response.data.decode()

    def test_calc_endpoint_blocks_file_access(self, client):
        """Test that /calc endpoint blocks file access attempts"""
        response = client.get('/calc?expr=open("/etc/passwd")')
        assert response.status_code == 400
        assert 'Error' in response.data.decode()

    def test_calc_endpoint_blocks_globals_access(self, client):
        """Test that /calc endpoint blocks globals() access"""
        response = client.get('/calc?expr=globals()')
        assert response.status_code == 400
        assert 'Error' in response.data.decode()

    def test_calc_endpoint_blocks_dunder_attributes(self, client):
        """Test that /calc endpoint blocks dunder attribute access"""
        response = client.get('/calc?expr=().__class__.__bases__')
        assert response.status_code == 400
        assert 'Error' in response.data.decode()

    def test_calc_endpoint_blocks_lambda(self, client):
        """Test that /calc endpoint blocks lambda expressions"""
        response = client.get('/calc?expr=(lambda:1)()')
        assert response.status_code == 400
        assert 'Error' in response.data.decode()

    def test_calc_endpoint_blocks_comprehension(self, client):
        """Test that /calc endpoint blocks list comprehensions"""
        response = client.get('/calc?expr=[1 for i in range(10)]')
        assert response.status_code == 400
        assert 'Error' in response.data.decode()

    def test_calc_endpoint_sql_injection_attempt(self, client):
        """Test that SQL-like injection attempts are blocked"""
        response = client.get('/calc?expr=1; DROP TABLE users')
        assert response.status_code == 400
        assert 'Error' in response.data.decode()

    def test_calc_endpoint_command_injection_attempt(self, client):
        """Test that command injection attempts are blocked"""
        response = client.get('/calc?expr=1; rm -rf /')
        assert response.status_code == 400
        assert 'Error' in response.data.decode()

    # ========================================================================
    # ERROR HANDLING TEST CASES
    # ========================================================================

    def test_calc_endpoint_syntax_error(self, client):
        """Test /calc endpoint with syntax error returns 400"""
        response = client.get('/calc?expr=2++3')
        assert response.status_code == 400
        assert 'Error' in response.data.decode()

    def test_calc_endpoint_division_by_zero(self, client):
        """Test /calc endpoint with division by zero returns 400"""
        response = client.get('/calc?expr=1/0')
        assert response.status_code == 400
        assert 'Error' in response.data.decode()

    def test_calc_endpoint_incomplete_expression(self, client):
        """Test /calc endpoint with incomplete expression returns 400"""
        response = client.get('/calc?expr=2+')
        assert response.status_code == 400
        assert 'Error' in response.data.decode()

    def test_calc_endpoint_empty_expression(self, client):
        """Test /calc endpoint with empty expression returns 400"""
        response = client.get('/calc?expr=')
        assert response.status_code == 400
        assert 'Error' in response.data.decode()

    # ========================================================================
    # REGRESSION TESTS - Ensure fix doesn't break functionality
    # ========================================================================

    def test_calc_maintains_mathematical_accuracy(self, client):
        """Regression test: Ensure mathematical operations remain accurate"""
        test_cases = [
            ('1+1', '2'),
            ('10-5', '5'),
            ('3*7', '21'),
            ('100/4', '25.0'),
            ('2**8', '256'),
            ('17%5', '2'),
        ]
        for expr, expected in test_cases:
            response = client.get(f'/calc?expr={expr}')
            assert response.status_code == 200
            assert response.data.decode() == expected

    def test_calc_handles_order_of_operations(self, client):
        """Regression test: Ensure order of operations is maintained"""
        response = client.get('/calc?expr=2+3*4')
        assert response.status_code == 200
        assert response.data.decode() == '14'  # Not 20

    def test_calc_respects_parentheses(self, client):
        """Regression test: Ensure parentheses affect order of operations"""
        response = client.get('/calc?expr=(2+3)*4')
        assert response.status_code == 200
        assert response.data.decode() == '20'  # Not 14


class TestSecurityBoundaries:
    """Additional security boundary tests for the code injection fix"""

    def test_no_access_to_builtins(self):
        """Test that __builtins__ cannot be accessed"""
        with pytest.raises(ValueError):
            safe_eval_expr("__builtins__")

    def test_no_dict_access(self):
        """Test that dict operations are blocked"""
        with pytest.raises(ValueError):
            safe_eval_expr("{'key': 'value'}")

    def test_no_list_access(self):
        """Test that list operations are blocked"""
        with pytest.raises(ValueError):
            safe_eval_expr("[1, 2, 3]")

    def test_no_tuple_access(self):
        """Test that tuple literals are blocked"""
        with pytest.raises(ValueError):
            safe_eval_expr("(1, 2, 3)")

    def test_no_set_access(self):
        """Test that set operations are blocked"""
        with pytest.raises(ValueError):
            safe_eval_expr("{1, 2, 3}")

    def test_only_safe_operators_allowed(self):
        """Test that only operators in SAFE_OPERATORS are allowed"""
        # This test verifies the whitelist approach
        safe_ops = ['+', '-', '*', '/', '//', '%', '**']
        unsafe_ops = ['&', '|', '^', '<<', '>>', '<', '>', '==', '!=', '<=', '>=', 'and', 'or', 'not', 'in', 'is']

        # Safe operators should work
        for op in safe_ops:
            if op == '**':
                safe_eval_expr(f"2 {op} 3")
            else:
                safe_eval_expr(f"10 {op} 5")

        # Unsafe operators should be blocked
        for op in unsafe_ops:
            with pytest.raises(ValueError):
                if op in ['and', 'or', 'not', 'in', 'is']:
                    safe_eval_expr(f"True {op} False")
                else:
                    safe_eval_expr(f"5 {op} 3")
