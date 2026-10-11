using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Auth4.Internal
{
    /// <summary>
    /// Minimal JSON reader and flat-object writer. Unity's JsonUtility is engine-only and
    /// System.Text.Json is not available in every supported Unity profile.
    /// </summary>
    internal static class Auth4Json
    {
        private const int MaxDepth = 16;

        /// <summary>Parses a JSON object, or returns null if the text is not a JSON object.</summary>
        public static Dictionary<string, object> TryParseObject(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return null;
            }

            try
            {
                var reader = new Reader(text);
                var value = reader.ReadValue(0);
                reader.SkipWhitespace();
                return reader.AtEnd ? value as Dictionary<string, object> : null;
            }
            catch (FormatException)
            {
                return null;
            }
        }

        public static string GetString(Dictionary<string, object> json, string key)
        {
            return json != null && json.TryGetValue(key, out var value) ? value as string : null;
        }

        public static double? GetNumber(Dictionary<string, object> json, string key)
        {
            return json != null && json.TryGetValue(key, out var value) && value is double number ? number : (double?)null;
        }

        public static Dictionary<string, object> GetObject(Dictionary<string, object> json, string key)
        {
            return json != null && json.TryGetValue(key, out var value) ? value as Dictionary<string, object> : null;
        }

        public static string SerializeStrings(IEnumerable<KeyValuePair<string, string>> values)
        {
            var builder = new StringBuilder("{");
            var first = true;
            foreach (var pair in values)
            {
                if (!first)
                {
                    builder.Append(',');
                }

                first = false;
                WriteString(builder, pair.Key);
                builder.Append(':');
                if (pair.Value == null)
                {
                    builder.Append("null");
                }
                else
                {
                    WriteString(builder, pair.Value);
                }
            }

            return builder.Append('}').ToString();
        }

        private static void WriteString(StringBuilder builder, string value)
        {
            builder.Append('"');
            foreach (var ch in value)
            {
                switch (ch)
                {
                    case '"': builder.Append("\\\""); break;
                    case '\\': builder.Append("\\\\"); break;
                    case '\b': builder.Append("\\b"); break;
                    case '\f': builder.Append("\\f"); break;
                    case '\n': builder.Append("\\n"); break;
                    case '\r': builder.Append("\\r"); break;
                    case '\t': builder.Append("\\t"); break;
                    default:
                        if (ch < 0x20 || ch == (char)0x2028 || ch == (char)0x2029)
                        {
                            builder.Append("\\u").Append(((int)ch).ToString("x4", CultureInfo.InvariantCulture));
                        }
                        else
                        {
                            builder.Append(ch);
                        }

                        break;
                }
            }

            builder.Append('"');
        }

        private sealed class Reader
        {
            private readonly string _text;
            private int _position;

            public Reader(string text)
            {
                _text = text;
            }

            public bool AtEnd => _position >= _text.Length;

            public void SkipWhitespace()
            {
                while (!AtEnd && (_text[_position] == ' ' || _text[_position] == '\t' ||
                                  _text[_position] == '\n' || _text[_position] == '\r'))
                {
                    _position++;
                }
            }

            public object ReadValue(int depth)
            {
                if (depth > MaxDepth)
                {
                    throw new FormatException("JSON nesting is too deep.");
                }

                SkipWhitespace();
                if (AtEnd)
                {
                    throw new FormatException("Unexpected end of JSON.");
                }

                var ch = _text[_position];
                switch (ch)
                {
                    case '{': return ReadObject(depth);
                    case '[': return ReadArray(depth);
                    case '"': return ReadString();
                    case 't': Expect("true"); return true;
                    case 'f': Expect("false"); return false;
                    case 'n': Expect("null"); return null;
                    default:
                        if (ch == '-' || (ch >= '0' && ch <= '9'))
                        {
                            return ReadNumber();
                        }

                        throw new FormatException("Unexpected JSON character.");
                }
            }

            private Dictionary<string, object> ReadObject(int depth)
            {
                var result = new Dictionary<string, object>(StringComparer.Ordinal);
                _position++;
                SkipWhitespace();
                if (!AtEnd && _text[_position] == '}')
                {
                    _position++;
                    return result;
                }

                while (true)
                {
                    SkipWhitespace();
                    if (AtEnd || _text[_position] != '"')
                    {
                        throw new FormatException("Expected a JSON property name.");
                    }

                    var key = ReadString();
                    SkipWhitespace();
                    Consume(':');
                    result[key] = ReadValue(depth + 1);
                    SkipWhitespace();
                    if (AtEnd)
                    {
                        throw new FormatException("Unterminated JSON object.");
                    }

                    if (_text[_position] == ',')
                    {
                        _position++;
                        continue;
                    }

                    Consume('}');
                    return result;
                }
            }

            private List<object> ReadArray(int depth)
            {
                var result = new List<object>();
                _position++;
                SkipWhitespace();
                if (!AtEnd && _text[_position] == ']')
                {
                    _position++;
                    return result;
                }

                while (true)
                {
                    result.Add(ReadValue(depth + 1));
                    SkipWhitespace();
                    if (AtEnd)
                    {
                        throw new FormatException("Unterminated JSON array.");
                    }

                    if (_text[_position] == ',')
                    {
                        _position++;
                        continue;
                    }

                    Consume(']');
                    return result;
                }
            }

            private string ReadString()
            {
                Consume('"');
                var builder = new StringBuilder();
                while (true)
                {
                    if (AtEnd)
                    {
                        throw new FormatException("Unterminated JSON string.");
                    }

                    var ch = _text[_position++];
                    if (ch == '"')
                    {
                        return builder.ToString();
                    }

                    if (ch < 0x20)
                    {
                        throw new FormatException("Control character in JSON string.");
                    }

                    if (ch != '\\')
                    {
                        builder.Append(ch);
                        continue;
                    }

                    if (AtEnd)
                    {
                        throw new FormatException("Unterminated JSON escape.");
                    }

                    var escape = _text[_position++];
                    switch (escape)
                    {
                        case '"': builder.Append('"'); break;
                        case '\\': builder.Append('\\'); break;
                        case '/': builder.Append('/'); break;
                        case 'b': builder.Append('\b'); break;
                        case 'f': builder.Append('\f'); break;
                        case 'n': builder.Append('\n'); break;
                        case 'r': builder.Append('\r'); break;
                        case 't': builder.Append('\t'); break;
                        case 'u':
                            if (_position + 4 > _text.Length ||
                                !int.TryParse(
                                    _text.Substring(_position, 4),
                                    NumberStyles.HexNumber,
                                    CultureInfo.InvariantCulture,
                                    out var code))
                            {
                                throw new FormatException("Invalid JSON unicode escape.");
                            }

                            builder.Append((char)code);
                            _position += 4;
                            break;
                        default:
                            throw new FormatException("Invalid JSON escape.");
                    }
                }
            }

            private double ReadNumber()
            {
                var start = _position;
                while (!AtEnd && "+-0123456789.eE".IndexOf(_text[_position]) >= 0)
                {
                    _position++;
                }

                if (!double.TryParse(
                        _text.Substring(start, _position - start),
                        NumberStyles.Float,
                        CultureInfo.InvariantCulture,
                        out var value))
                {
                    throw new FormatException("Invalid JSON number.");
                }

                return value;
            }

            private void Expect(string literal)
            {
                if (string.CompareOrdinal(_text, _position, literal, 0, literal.Length) != 0)
                {
                    throw new FormatException("Invalid JSON literal.");
                }

                _position += literal.Length;
            }

            private void Consume(char expected)
            {
                if (AtEnd || _text[_position] != expected)
                {
                    throw new FormatException("Unexpected JSON token.");
                }

                _position++;
            }
        }
    }
}
