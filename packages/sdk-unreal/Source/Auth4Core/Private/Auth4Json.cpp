#include "Auth4Json.h"

#include <cmath>
#include <cstdint>

namespace Auth4
{
    namespace Json
    {
        namespace
        {
            constexpr int MaxJsonDepth = 32;

            class JsonParser
            {
            public:
                explicit JsonParser(const std::string& InText) : Text(InText) {}

                bool ParseRoot(Object& Out)
                {
                    SkipSpace();
                    if (!ParseObjectBody(Out, 0))
                    {
                        return false;
                    }

                    SkipSpace();
                    return Position == Text.size();
                }

            private:
                const std::string& Text;
                size_t Position = 0;

                void SkipSpace()
                {
                    while (Position < Text.size() &&
                           (Text[Position] == ' ' || Text[Position] == '\t' || Text[Position] == '\n' || Text[Position] == '\r'))
                    {
                        ++Position;
                    }
                }

                bool Consume(char Expected)
                {
                    SkipSpace();
                    if (Position < Text.size() && Text[Position] == Expected)
                    {
                        ++Position;
                        return true;
                    }

                    return false;
                }

                bool ParseObjectBody(Object& Out, int Depth)
                {
                    if (Depth > MaxJsonDepth || !Consume('{'))
                    {
                        return false;
                    }

                    if (Consume('}'))
                    {
                        return true;
                    }

                    for (;;)
                    {
                        SkipSpace();
                        std::string Key;
                        if (!ParseString(Key) || !Consume(':'))
                        {
                            return false;
                        }

                        Field Value;
                        if (!ParseValue(Value, Depth + 1))
                        {
                            return false;
                        }

                        Out.Fields[Key] = std::move(Value);
                        if (Consume(','))
                        {
                            continue;
                        }

                        return Consume('}');
                    }
                }

                bool ParseArrayBody(int Depth)
                {
                    if (Depth > MaxJsonDepth || !Consume('['))
                    {
                        return false;
                    }

                    if (Consume(']'))
                    {
                        return true;
                    }

                    for (;;)
                    {
                        Field Ignored;
                        if (!ParseValue(Ignored, Depth + 1))
                        {
                            return false;
                        }

                        if (Consume(','))
                        {
                            continue;
                        }

                        return Consume(']');
                    }
                }

                bool ParseValue(Field& Out, int Depth)
                {
                    SkipSpace();
                    if (Position >= Text.size())
                    {
                        return false;
                    }

                    const char Next = Text[Position];
                    if (Next == '"')
                    {
                        Out.Kind = Field::Type::String;
                        return ParseString(Out.Text);
                    }

                    if (Next == '{')
                    {
                        Out.Kind = Field::Type::Object;
                        Out.Child = std::make_shared<Object>();
                        return ParseObjectBody(*Out.Child, Depth);
                    }

                    if (Next == '[')
                    {
                        Out.Kind = Field::Type::Array;
                        return ParseArrayBody(Depth);
                    }

                    if (Text.compare(Position, 4, "true") == 0)
                    {
                        Position += 4;
                        Out.Kind = Field::Type::Bool;
                        Out.Flag = true;
                        return true;
                    }

                    if (Text.compare(Position, 5, "false") == 0)
                    {
                        Position += 5;
                        Out.Kind = Field::Type::Bool;
                        return true;
                    }

                    if (Text.compare(Position, 4, "null") == 0)
                    {
                        Position += 4;
                        Out.Kind = Field::Type::Null;
                        return true;
                    }

                    Out.Kind = Field::Type::Number;
                    return ParseNumber(Out.Number);
                }

                static bool IsDigit(char Value) { return Value >= '0' && Value <= '9'; }

                bool ParseNumber(double& Out)
                {
                    const size_t Start = Position;
                    bool bNegative = false;
                    if (Position < Text.size() && Text[Position] == '-')
                    {
                        bNegative = true;
                        ++Position;
                    }

                    if (Position >= Text.size() || !IsDigit(Text[Position]))
                    {
                        return false;
                    }

                    double Mantissa = 0;
                    while (Position < Text.size() && IsDigit(Text[Position]))
                    {
                        Mantissa = Mantissa * 10 + (Text[Position] - '0');
                        ++Position;
                    }

                    int Exponent = 0;
                    if (Position < Text.size() && Text[Position] == '.')
                    {
                        ++Position;
                        if (Position >= Text.size() || !IsDigit(Text[Position]))
                        {
                            return false;
                        }

                        while (Position < Text.size() && IsDigit(Text[Position]))
                        {
                            Mantissa = Mantissa * 10 + (Text[Position] - '0');
                            --Exponent;
                            ++Position;
                        }
                    }

                    if (Position < Text.size() && (Text[Position] == 'e' || Text[Position] == 'E'))
                    {
                        ++Position;
                        bool bNegativeExponent = false;
                        if (Position < Text.size() && (Text[Position] == '+' || Text[Position] == '-'))
                        {
                            bNegativeExponent = Text[Position] == '-';
                            ++Position;
                        }

                        if (Position >= Text.size() || !IsDigit(Text[Position]))
                        {
                            return false;
                        }

                        int Written = 0;
                        while (Position < Text.size() && IsDigit(Text[Position]))
                        {
                            Written = Written < 10000 ? Written * 10 + (Text[Position] - '0') : Written;
                            ++Position;
                        }

                        Exponent += bNegativeExponent ? -Written : Written;
                    }

                    Out = Mantissa * std::pow(10.0, Exponent);
                    if (bNegative)
                    {
                        Out = -Out;
                    }

                    return Position > Start && std::isfinite(Out);
                }

                bool ReadHex4(uint32_t& Out)
                {
                    if (Position + 4 > Text.size())
                    {
                        return false;
                    }

                    Out = 0;
                    for (int Index = 0; Index < 4; ++Index)
                    {
                        const char Digit = Text[Position++];
                        Out <<= 4;
                        if (Digit >= '0' && Digit <= '9')
                        {
                            Out |= static_cast<uint32_t>(Digit - '0');
                        }
                        else if (Digit >= 'a' && Digit <= 'f')
                        {
                            Out |= static_cast<uint32_t>(Digit - 'a' + 10);
                        }
                        else if (Digit >= 'A' && Digit <= 'F')
                        {
                            Out |= static_cast<uint32_t>(Digit - 'A' + 10);
                        }
                        else
                        {
                            return false;
                        }
                    }

                    return true;
                }

                static void AppendUtf8(std::string& Out, uint32_t CodePoint)
                {
                    if (CodePoint < 0x80)
                    {
                        Out.push_back(static_cast<char>(CodePoint));
                    }
                    else if (CodePoint < 0x800)
                    {
                        Out.push_back(static_cast<char>(0xC0 | (CodePoint >> 6)));
                        Out.push_back(static_cast<char>(0x80 | (CodePoint & 0x3F)));
                    }
                    else if (CodePoint < 0x10000)
                    {
                        Out.push_back(static_cast<char>(0xE0 | (CodePoint >> 12)));
                        Out.push_back(static_cast<char>(0x80 | ((CodePoint >> 6) & 0x3F)));
                        Out.push_back(static_cast<char>(0x80 | (CodePoint & 0x3F)));
                    }
                    else
                    {
                        Out.push_back(static_cast<char>(0xF0 | (CodePoint >> 18)));
                        Out.push_back(static_cast<char>(0x80 | ((CodePoint >> 12) & 0x3F)));
                        Out.push_back(static_cast<char>(0x80 | ((CodePoint >> 6) & 0x3F)));
                        Out.push_back(static_cast<char>(0x80 | (CodePoint & 0x3F)));
                    }
                }

                bool ParseString(std::string& Out)
                {
                    if (Position >= Text.size() || Text[Position] != '"')
                    {
                        return false;
                    }

                    ++Position;
                    Out.clear();
                    while (Position < Text.size())
                    {
                        const char Next = Text[Position++];
                        if (Next == '"')
                        {
                            return true;
                        }

                        if (static_cast<unsigned char>(Next) < 0x20)
                        {
                            return false;
                        }

                        if (Next != '\\')
                        {
                            Out.push_back(Next);
                            continue;
                        }

                        if (Position >= Text.size())
                        {
                            return false;
                        }

                        const char Escape = Text[Position++];
                        switch (Escape)
                        {
                        case '"': Out.push_back('"'); break;
                        case '\\': Out.push_back('\\'); break;
                        case '/': Out.push_back('/'); break;
                        case 'b': Out.push_back('\b'); break;
                        case 'f': Out.push_back('\f'); break;
                        case 'n': Out.push_back('\n'); break;
                        case 'r': Out.push_back('\r'); break;
                        case 't': Out.push_back('\t'); break;
                        case 'u':
                        {
                            uint32_t CodePoint = 0;
                            if (!ReadHex4(CodePoint))
                            {
                                return false;
                            }

                            if (CodePoint >= 0xD800 && CodePoint <= 0xDBFF)
                            {
                                uint32_t Low = 0;
                                if (Position + 2 > Text.size() || Text[Position] != '\\' || Text[Position + 1] != 'u')
                                {
                                    return false;
                                }

                                Position += 2;
                                if (!ReadHex4(Low) || Low < 0xDC00 || Low > 0xDFFF)
                                {
                                    return false;
                                }

                                CodePoint = 0x10000 + ((CodePoint - 0xD800) << 10) + (Low - 0xDC00);
                            }
                            else if (CodePoint >= 0xDC00 && CodePoint <= 0xDFFF)
                            {
                                return false;
                            }

                            AppendUtf8(Out, CodePoint);
                            break;
                        }
                        default:
                            return false;
                        }
                    }

                    return false;
                }
            };
        }

        std::shared_ptr<Object> ParseObject(const std::string& Text)
        {
            auto Out = std::make_shared<Object>();
            JsonParser Parser(Text);
            return Parser.ParseRoot(*Out) ? Out : nullptr;
        }

        std::optional<std::string> GetString(const Object* Value, const std::string& Key)
        {
            if (Value == nullptr)
            {
                return std::nullopt;
            }

            const auto Found = Value->Fields.find(Key);
            if (Found == Value->Fields.end() || Found->second.Kind != Field::Type::String)
            {
                return std::nullopt;
            }

            return Found->second.Text;
        }

        std::optional<double> GetNumber(const Object* Value, const std::string& Key)
        {
            if (Value == nullptr)
            {
                return std::nullopt;
            }

            const auto Found = Value->Fields.find(Key);
            if (Found == Value->Fields.end() || Found->second.Kind != Field::Type::Number)
            {
                return std::nullopt;
            }

            return Found->second.Number;
        }

        const Object* GetObject(const Object* Value, const std::string& Key)
        {
            if (Value == nullptr)
            {
                return nullptr;
            }

            const auto Found = Value->Fields.find(Key);
            if (Found == Value->Fields.end() || Found->second.Kind != Field::Type::Object)
            {
                return nullptr;
            }

            return Found->second.Child.get();
        }

        std::string SerializeStrings(const std::vector<std::pair<std::string, std::string>>& Values)
        {
            static const char HexDigits[] = "0123456789abcdef";
            std::string Out = "{";
            bool bFirst = true;
            for (const auto& Entry : Values)
            {
                if (!bFirst)
                {
                    Out.push_back(',');
                }

                bFirst = false;
                for (int Part = 0; Part < 2; ++Part)
                {
                    const std::string& Text = Part == 0 ? Entry.first : Entry.second;
                    Out.push_back('"');
                    for (const char Character : Text)
                    {
                        const auto Code = static_cast<unsigned char>(Character);
                        if (Character == '"' || Character == '\\')
                        {
                            Out.push_back('\\');
                            Out.push_back(Character);
                        }
                        else if (Code < 0x20)
                        {
                            Out += "\\u00";
                            Out.push_back(HexDigits[Code >> 4]);
                            Out.push_back(HexDigits[Code & 0xF]);
                        }
                        else
                        {
                            Out.push_back(Character);
                        }
                    }

                    Out.push_back('"');
                    if (Part == 0)
                    {
                        Out.push_back(':');
                    }
                }
            }

            Out.push_back('}');
            return Out;
        }
    }
}
