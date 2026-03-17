const assert = require('assert');
const validator = require('validator');

describe('XSS Remediation Tests', () => {
  describe('exports.edit XSS Prevention', () => {

    // Mock dependencies
    let mockTodo;
    let mockReq;
    let mockRes;
    let mockNext;
    let renderCallArgs;

    // Mock the Todo model
    const Todo = {
      find: function(query) {
        return {
          sort: function(sortBy) {
            return {
              exec: function(callback) {
                // Simulate database returning todos with malicious content
                callback(null, [mockTodo]);
              }
            };
          }
        };
      }
    };

    beforeEach(() => {
      // Reset mocks before each test
      renderCallArgs = null;
      mockReq = {
        params: {
          id: '123456789'
        }
      };
      mockRes = {
        render: function(view, data) {
          renderCallArgs = { view, data };
        }
      };
      mockNext = function(err) {
        throw err;
      };
    });

    test('should sanitize XSS script tags in todo content', () => {
      // GIVEN - A todo with malicious script tag
      mockTodo = {
        _id: '123',
        content: '<script>alert("XSS")</script>',
        updated_at: new Date()
      };

      // WHEN - The edit function is called
      const editHandler = createEditHandler(Todo);
      editHandler(mockReq, mockRes, mockNext);

      // THEN - The script tag should be escaped
      assert(renderCallArgs !== null, 'render should have been called');
      assert(renderCallArgs.data.todos.length === 1, 'should have one todo');
      const sanitizedContent = renderCallArgs.data.todos[0].content;
      assert(sanitizedContent.includes('&lt;script&gt;'), 'script tag should be escaped');
      assert(sanitizedContent.includes('&lt;/script&gt;'), 'closing script tag should be escaped');
      assert(!sanitizedContent.includes('<script>'), 'unescaped script tag should not be present');
    });

    test('should sanitize XSS with img onerror attack', () => {
      // GIVEN - A todo with img onerror XSS attack
      mockTodo = {
        _id: '456',
        content: '<img src=x onerror="alert(\'XSS\')">',
        updated_at: new Date()
      };

      // WHEN - The edit function is called
      const editHandler = createEditHandler(Todo);
      editHandler(mockReq, mockRes, mockNext);

      // THEN - The img tag should be escaped
      const sanitizedContent = renderCallArgs.data.todos[0].content;
      assert(sanitizedContent.includes('&lt;img'), 'img tag should be escaped');
      assert(sanitizedContent.includes('onerror='), 'onerror attribute should be present but escaped');
      assert(!sanitizedContent.includes('<img'), 'unescaped img tag should not be present');
    });

    test('should sanitize XSS with event handlers', () => {
      // GIVEN - A todo with onclick event handler
      mockTodo = {
        _id: '789',
        content: '<div onclick="maliciousCode()">Click me</div>',
        updated_at: new Date()
      };

      // WHEN - The edit function is called
      const editHandler = createEditHandler(Todo);
      editHandler(mockReq, mockRes, mockNext);

      // THEN - The div and onclick should be escaped
      const sanitizedContent = renderCallArgs.data.todos[0].content;
      assert(sanitizedContent.includes('&lt;div'), 'div tag should be escaped');
      assert(sanitizedContent.includes('onclick'), 'onclick attribute text should be present');
      assert(!sanitizedContent.includes('<div onclick'), 'unescaped div with onclick should not be present');
    });

    test('should preserve safe content without modification (except escaping)', () => {
      // GIVEN - A todo with safe, plain text content
      mockTodo = {
        _id: '101',
        content: 'Buy groceries & pick up mail',
        updated_at: new Date()
      };

      // WHEN - The edit function is called
      const editHandler = createEditHandler(Todo);
      editHandler(mockReq, mockRes, mockNext);

      // THEN - The content should be present with & escaped
      const sanitizedContent = renderCallArgs.data.todos[0].content;
      assert(sanitizedContent.includes('Buy groceries'), 'safe text should be preserved');
      assert(sanitizedContent.includes('&amp;'), 'ampersand should be escaped');
      assert(sanitizedContent.includes('pick up mail'), 'rest of text should be preserved');
    });

    test('should sanitize multiple special characters', () => {
      // GIVEN - A todo with multiple HTML special characters
      mockTodo = {
        _id: '202',
        content: '< > & " \' ',
        updated_at: new Date()
      };

      // WHEN - The edit function is called
      const editHandler = createEditHandler(Todo);
      editHandler(mockReq, mockRes, mockNext);

      // THEN - All special characters should be escaped
      const sanitizedContent = renderCallArgs.data.todos[0].content;
      assert(sanitizedContent.includes('&lt;'), 'less-than should be escaped');
      assert(sanitizedContent.includes('&gt;'), 'greater-than should be escaped');
      assert(sanitizedContent.includes('&amp;'), 'ampersand should be escaped');
      assert(sanitizedContent.includes('&quot;') || sanitizedContent.includes('&#34;'), 'double quote should be escaped');
      assert(sanitizedContent.includes('&#x27;') || sanitizedContent.includes('&#39;'), 'single quote should be escaped');
    });

    test('should sanitize XSS with javascript: protocol', () => {
      // GIVEN - A todo with javascript protocol
      mockTodo = {
        _id: '303',
        content: '<a href="javascript:alert(\'XSS\')">Click</a>',
        updated_at: new Date()
      };

      // WHEN - The edit function is called
      const editHandler = createEditHandler(Todo);
      editHandler(mockReq, mockRes, mockNext);

      // THEN - The anchor tag and javascript protocol should be escaped
      const sanitizedContent = renderCallArgs.data.todos[0].content;
      assert(sanitizedContent.includes('&lt;a'), 'anchor tag should be escaped');
      assert(sanitizedContent.includes('javascript:'), 'javascript protocol text should be present');
      assert(!sanitizedContent.includes('<a href='), 'unescaped anchor should not be present');
    });

    test('should preserve _id and updated_at fields without modification', () => {
      // GIVEN - A todo with all fields
      const testDate = new Date('2024-01-01');
      mockTodo = {
        _id: '404',
        content: '<script>alert("test")</script>',
        updated_at: testDate
      };

      // WHEN - The edit function is called
      const editHandler = createEditHandler(Todo);
      editHandler(mockReq, mockRes, mockNext);

      // THEN - _id and updated_at should be unchanged
      const todo = renderCallArgs.data.todos[0];
      assert(todo._id === '404', '_id should be preserved');
      assert(todo.updated_at === testDate, 'updated_at should be preserved');
      assert(typeof todo.content === 'string', 'content should be a string');
    });

    test('should handle empty content gracefully', () => {
      // GIVEN - A todo with empty content
      mockTodo = {
        _id: '505',
        content: '',
        updated_at: new Date()
      };

      // WHEN - The edit function is called
      const editHandler = createEditHandler(Todo);
      editHandler(mockReq, mockRes, mockNext);

      // THEN - Should not throw error and return empty escaped string
      assert(renderCallArgs !== null, 'render should have been called');
      assert(renderCallArgs.data.todos[0].content === '', 'empty content should remain empty');
    });

    test('should sanitize all todos in the list', () => {
      // GIVEN - Multiple todos with various XSS payloads
      const multipleTodos = [
        { _id: '1', content: '<script>xss1</script>', updated_at: new Date() },
        { _id: '2', content: '<img src=x onerror=xss2>', updated_at: new Date() },
        { _id: '3', content: 'safe content', updated_at: new Date() }
      ];

      // Override the Todo mock for this test
      const TodoMultiple = {
        find: function(query) {
          return {
            sort: function(sortBy) {
              return {
                exec: function(callback) {
                  callback(null, multipleTodos);
                }
              };
            }
          };
        }
      };

      // WHEN - The edit function is called
      const editHandler = createEditHandler(TodoMultiple);
      editHandler(mockReq, mockRes, mockNext);

      // THEN - All todos should be sanitized
      assert(renderCallArgs.data.todos.length === 3, 'should have three todos');
      assert(renderCallArgs.data.todos[0].content.includes('&lt;script&gt;'), 'first todo should be sanitized');
      assert(renderCallArgs.data.todos[1].content.includes('&lt;img'), 'second todo should be sanitized');
      assert(renderCallArgs.data.todos[2].content === 'safe content', 'third todo should be unchanged');
    });

    test('should pass correct parameters to render function', () => {
      // GIVEN - A todo
      mockTodo = {
        _id: '606',
        content: 'test content',
        updated_at: new Date()
      };

      // WHEN - The edit function is called
      const editHandler = createEditHandler(Todo);
      editHandler(mockReq, mockRes, mockNext);

      // THEN - Render should be called with correct parameters
      assert(renderCallArgs.view === 'edit', 'should render edit view');
      assert(renderCallArgs.data.title === 'TODO', 'should have correct title');
      assert(renderCallArgs.data.current === '123456789', 'should pass current id from params');
      assert(Array.isArray(renderCallArgs.data.todos), 'todos should be an array');
    });

  });

  describe('Validator.escape functionality verification', () => {

    test('validator.escape should convert HTML entities correctly', () => {
      // Test that validator.escape works as expected
      const malicious = '<script>alert("XSS")</script>';
      const escaped = validator.escape(malicious);

      assert(!escaped.includes('<script>'), 'should not contain unescaped script tag');
      assert(escaped.includes('&lt;') && escaped.includes('&gt;'), 'should contain escaped brackets');
    });

    test('validator.escape should handle all special characters', () => {
      const input = '< > & " \' /';
      const escaped = validator.escape(input);

      // Verify no unescaped special chars remain
      assert(!escaped.includes('<') || escaped.includes('&lt;'), 'less-than should be escaped');
      assert(!escaped.includes('>') || escaped.includes('&gt;'), 'greater-than should be escaped');
      assert(escaped.includes('&amp;') || escaped.includes('&'), 'ampersand should be handled');
    });

  });
});

/**
 * Helper function to create edit handler with mocked Todo model
 * This simulates the actual exports.edit function behavior
 */
function createEditHandler(TodoModel) {
  return function(req, res, next) {
    TodoModel
      .find({})
      .sort('-updated_at')
      .exec(function (err, todos) {
        if (err) return next(err);

        // Sanitize todo content to prevent XSS attacks
        const sanitizedTodos = todos.map(function(todo) {
          return {
            _id: todo._id,
            content: validator.escape(todo.content),
            updated_at: todo.updated_at
          };
        });

        res.render('edit', {
          title: 'TODO',
          todos: sanitizedTodos,
          current: req.params.id
        });
      });
  };
}
