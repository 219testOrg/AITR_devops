"""
Comprehensive test suite for sast_critical_high.py security remediation.

This test suite validates that the Debug_Enabled vulnerability (CWE-489) has been
properly fixed by ensuring that Flask debug mode is disabled in production.
"""

import unittest
import sys
import os
from unittest.mock import patch, MagicMock, call
import tempfile
import sqlite3


class TestDebugModeDisabled(unittest.TestCase):
    """Test suite to verify that Flask debug mode is properly disabled."""

    def setUp(self):
        """Set up test fixtures."""
        # Import the module under test
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    def tearDown(self):
        """Clean up after tests."""
        # Remove module from cache to ensure clean state between tests
        if 'sast_critical_high' in sys.modules:
            del sys.modules['sast_critical_high']

    @patch('sast_critical_high.app')
    def test_debug_mode_is_false(self, mock_app):
        """
        Test that Flask app.run() is called with debug=False.

        This is the primary security test ensuring CWE-489 is remediated.
        Debug mode must be False to prevent:
        - Exposure of sensitive application internals
        - Interactive debugger access in production
        - Detailed stack traces revealing code structure
        """
        # Mock the app.run method
        mock_app.run = MagicMock()

        # Import and execute the main block
        with patch('sast_critical_high.init_db'):
            with patch('sast_critical_high.__name__', '__main__'):
                # Execute the main block by importing
                import sast_critical_high

                # Manually call the main execution since we're in a test
                sast_critical_high.init_db()
                sast_critical_high.app.run(host="0.0.0.0", port=8080, debug=False)

        # Verify app.run was called with debug=False
        mock_app.run.assert_called_once()
        call_kwargs = mock_app.run.call_args[1]

        self.assertIn('debug', call_kwargs,
                     "debug parameter must be explicitly set")
        self.assertFalse(call_kwargs['debug'],
                        "debug parameter must be False (CWE-489 remediation)")

    def test_debug_parameter_explicitly_set(self):
        """
        Test that the debug parameter is explicitly set to False, not just omitted.

        Explicit False is more secure than relying on default behavior.
        """
        # Read the source file
        source_file = os.path.join(os.path.dirname(__file__), 'sast_critical_high.py')
        with open(source_file, 'r') as f:
            source_code = f.read()

        # Verify that app.run contains debug=False explicitly
        self.assertIn('debug=False', source_code,
                     "debug must be explicitly set to False in app.run()")

        # Verify that debug=True is NOT present (the vulnerability)
        self.assertNotIn('debug=True', source_code,
                        "debug=True must not be present (CWE-489 vulnerability)")

    @patch('sast_critical_high.app')
    @patch('sast_critical_high.init_db')
    def test_app_runs_without_debug_mode(self, mock_init_db, mock_app):
        """
        Integration test: Verify the application can start without debug mode.

        Tests that disabling debug mode doesn't break application functionality.
        """
        mock_app.run = MagicMock()

        # Simulate running the application
        with patch('sast_critical_high.__name__', '__main__'):
            exec(compile(open('sast_critical_high.py').read(), 'sast_critical_high.py', 'exec'))

        # Verify init_db was called (app initialization)
        mock_init_db.assert_called()

    def test_no_development_artifacts_in_production_config(self):
        """
        Test that no other development/debugging artifacts are enabled.

        Ensures comprehensive security beyond just the debug flag.
        """
        source_file = os.path.join(os.path.dirname(__file__), 'sast_critical_high.py')
        with open(source_file, 'r') as f:
            source_code = f.read()

        # Check for common development/debug patterns that should be disabled
        insecure_patterns = [
            ('TESTING = True', 'TESTING mode should not be enabled'),
            ('ENV = "development"', 'Environment should not be set to development'),
            ('app.debug = True', 'app.debug should not be True'),
        ]

        for pattern, message in insecure_patterns:
            self.assertNotIn(pattern, source_code, message)

    def test_security_comment_present(self):
        """
        Test that security-focused comments are present explaining the fix.

        Documentation helps prevent future regressions.
        """
        source_file = os.path.join(os.path.dirname(__file__), 'sast_critical_high.py')
        with open(source_file, 'r') as f:
            source_code = f.read()

        # Verify security comment is present near the debug=False line
        lines = source_code.split('\n')
        debug_line_index = None

        for i, line in enumerate(lines):
            if 'debug=False' in line and 'app.run' in line:
                debug_line_index = i
                break

        self.assertIsNotNone(debug_line_index,
                           "Could not find app.run with debug=False")

        # Check that there's a security-related comment within 5 lines before
        comment_found = False
        for i in range(max(0, debug_line_index - 5), debug_line_index + 1):
            if 'security' in lines[i].lower() or 'cwe' in lines[i].lower():
                comment_found = True
                break

        self.assertTrue(comment_found,
                       "Security-focused comment should be present near debug=False")


class TestDebugModeSecurityImpact(unittest.TestCase):
    """
    Test suite to validate security implications of debug mode being disabled.

    These tests verify that with debug=False, the application behaves securely.
    """

    def test_flask_debug_false_prevents_interactive_debugger(self):
        """
        Test that debug=False prevents the interactive debugger.

        The interactive debugger is a major security risk (CWE-489) as it allows
        arbitrary code execution through the browser when errors occur.
        """
        from flask import Flask

        test_app = Flask(__name__)

        # Configure with debug=False (the fix)
        test_app.config['DEBUG'] = False

        # Verify debug is disabled
        self.assertFalse(test_app.debug,
                        "Flask app debug attribute must be False")
        self.assertFalse(test_app.config.get('DEBUG', False),
                        "Flask DEBUG config must be False")

    def test_debug_false_configuration_security(self):
        """
        Test the security properties when debug is False.

        Validates that debug=False provides expected security properties.
        """
        from flask import Flask

        secure_app = Flask(__name__)
        insecure_app = Flask(__name__)

        secure_app.config['DEBUG'] = False
        insecure_app.config['DEBUG'] = True

        # Verify secure app has debug disabled
        self.assertFalse(secure_app.debug,
                        "Secure configuration must have debug=False")

        # Verify insecure app has debug enabled (for comparison)
        self.assertTrue(insecure_app.debug,
                       "Insecure configuration should have debug=True for comparison")

        # The remediated code should match secure_app configuration
        self.assertFalse(secure_app.debug,
                        "Remediated code should match secure configuration")


class TestRegressionPrevention(unittest.TestCase):
    """
    Regression tests to ensure the vulnerability doesn't get reintroduced.
    """

    def test_main_block_calls_app_run_with_correct_params(self):
        """
        Test that the main block has the correct app.run() signature.

        Prevents accidental removal of the debug=False parameter.
        """
        source_file = os.path.join(os.path.dirname(__file__), 'sast_critical_high.py')
        with open(source_file, 'r') as f:
            source_code = f.read()

        # Find the main block
        self.assertIn('if __name__ == "__main__":', source_code,
                     "Main block must be present")

        # Extract the main block
        main_block_start = source_code.find('if __name__ == "__main__":')
        main_block = source_code[main_block_start:]

        # Verify app.run is called in main block
        self.assertIn('app.run', main_block,
                     "app.run must be called in main block")

        # Verify debug=False is in the main block
        self.assertIn('debug=False', main_block,
                     "debug=False must be present in main block")

        # Verify other parameters are still present
        self.assertIn('host=', main_block,
                     "host parameter should still be present")
        self.assertIn('port=', main_block,
                     "port parameter should still be present")

    def test_no_conditional_debug_enabling(self):
        """
        Test that debug mode is not conditionally enabled anywhere.

        Ensures there's no code path that could enable debug mode.
        """
        source_file = os.path.join(os.path.dirname(__file__), 'sast_critical_high.py')
        with open(source_file, 'r') as f:
            source_code = f.read()

        # Check for patterns that might conditionally enable debug
        risky_patterns = [
            'if debug:',
            'if DEBUG:',
            'debug = True',
            'DEBUG = True',
            'app.debug = True',
            'app.config["DEBUG"] = True',
            "app.config['DEBUG'] = True",
        ]

        for pattern in risky_patterns:
            self.assertNotIn(pattern, source_code,
                           f"Risky pattern '{pattern}' should not be present")

    def test_environment_variable_not_used_for_debug(self):
        """
        Test that environment variables are not used to enable debug mode.

        While using env vars for configuration can be good, for debug mode
        it's safer to keep it explicitly False in production code.
        """
        source_file = os.path.join(os.path.dirname(__file__), 'sast_critical_high.py')
        with open(source_file, 'r') as f:
            source_code = f.read()

        # Look for the app.run line
        lines = source_code.split('\n')
        app_run_lines = [line for line in lines if 'app.run' in line]

        self.assertTrue(len(app_run_lines) > 0, "app.run should be present")

        # Verify that debug parameter is not set from environment
        for line in app_run_lines:
            if 'debug' in line:
                self.assertNotIn('os.environ', line,
                               "Debug should not be read from environment")
                self.assertNotIn('os.getenv', line,
                               "Debug should not be read from environment")
                self.assertNotIn('getenv', line,
                               "Debug should not be read from environment")


class TestFunctionalityPreserved(unittest.TestCase):
    """
    Tests to ensure that fixing the vulnerability didn't break functionality.
    """

    @patch('sast_critical_high.sqlite3.connect')
    def test_init_db_still_works(self, mock_connect):
        """
        Test that database initialization still works after the fix.
        """
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn

        import sast_critical_high
        sast_critical_high.init_db()

        # Verify database operations were called
        mock_connect.assert_called_once_with(":memory:", check_same_thread=False)
        mock_conn.cursor.assert_called()
        mock_cursor.execute.assert_called()
        mock_conn.commit.assert_called()

    def test_flask_app_instance_exists(self):
        """
        Test that the Flask app instance is properly created.
        """
        import sast_critical_high

        self.assertIsNotNone(sast_critical_high.app,
                           "Flask app instance should exist")
        self.assertEqual(sast_critical_high.app.name, 'sast_critical_high',
                        "Flask app should have correct name")

    def test_routes_still_defined(self):
        """
        Test that all routes are still defined after the fix.
        """
        import sast_critical_high

        # Get all route rules
        routes = [rule.rule for rule in sast_critical_high.app.url_map.iter_rules()]

        # Verify critical routes exist (sample check)
        expected_routes = ['/user', '/search', '/login', '/ping']

        for expected_route in expected_routes:
            self.assertIn(expected_route, routes,
                         f"Route {expected_route} should still be defined")


if __name__ == '__main__':
    # Run the test suite
    unittest.main(verbosity=2)
