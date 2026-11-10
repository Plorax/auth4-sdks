#include "Auth4Url.h"

namespace Auth4
{
    namespace Url
    {
        namespace
        {
            std::string LowerAscii(std::string Value)
            {
                for (char& Character : Value)
                {
                    if (Character >= 'A' && Character <= 'Z')
                    {
                        Character = static_cast<char>(Character - 'A' + 'a');
                    }
                }

                return Value;
            }

            bool IsLoopbackHost(const std::string& Host)
            {
                return Host == "localhost" || Host == "[::1]" || Host.rfind("127.", 0) == 0;
            }
        }

        std::string Parts::Origin() const
        {
            const bool bDefaultPort = Port.empty() || (Scheme == "https" && Port == "443") || (Scheme == "http" && Port == "80");
            return Scheme + "://" + Host + (bDefaultPort ? std::string() : ":" + Port);
        }

        std::optional<Parts> Parse(const std::string& Value)
        {
            for (const char Character : Value)
            {
                const auto Code = static_cast<unsigned char>(Character);
                if (Code <= 0x20 || Code == 0x7F || Character == '\\')
                {
                    return std::nullopt;
                }
            }

            const size_t SchemeEnd = Value.find("://");
            if (SchemeEnd == std::string::npos)
            {
                return std::nullopt;
            }

            Parts Out;
            Out.Scheme = LowerAscii(Value.substr(0, SchemeEnd));
            if (Out.Scheme != "https" && Out.Scheme != "http")
            {
                return std::nullopt;
            }

            const size_t AuthorityStart = SchemeEnd + 3;
            size_t AuthorityEnd = Value.find_first_of("/?#", AuthorityStart);
            if (AuthorityEnd == std::string::npos)
            {
                AuthorityEnd = Value.size();
            }

            std::string Authority = Value.substr(AuthorityStart, AuthorityEnd - AuthorityStart);
            const size_t At = Authority.rfind('@');
            if (At != std::string::npos)
            {
                Out.UserInfo = Authority.substr(0, At);
                Authority = Authority.substr(At + 1);
            }

            size_t PortSeparator = std::string::npos;
            if (!Authority.empty() && Authority[0] == '[')
            {
                const size_t Close = Authority.find(']');
                if (Close == std::string::npos)
                {
                    return std::nullopt;
                }

                if (Close + 1 < Authority.size())
                {
                    if (Authority[Close + 1] != ':')
                    {
                        return std::nullopt;
                    }

                    PortSeparator = Close + 1;
                }
            }
            else
            {
                PortSeparator = Authority.find(':');
            }

            Out.Host = LowerAscii(Authority.substr(0, PortSeparator));
            if (PortSeparator != std::string::npos)
            {
                Out.Port = Authority.substr(PortSeparator + 1);
                if (Out.Port.empty() || Out.Port.size() > 5 || Out.Port.find_first_not_of("0123456789") != std::string::npos)
                {
                    return std::nullopt;
                }
            }

            if (Out.Host.empty())
            {
                return std::nullopt;
            }

            size_t Rest = AuthorityEnd;
            const size_t PathEnd = Value.find_first_of("?#", Rest);
            Out.Path = Value.substr(Rest, (PathEnd == std::string::npos ? Value.size() : PathEnd) - Rest);
            Rest = PathEnd == std::string::npos ? Value.size() : PathEnd;
            if (Rest < Value.size() && Value[Rest] == '?')
            {
                const size_t QueryEnd = Value.find('#', Rest);
                Out.bHasQuery = true;
                Out.Query = Value.substr(Rest + 1, (QueryEnd == std::string::npos ? Value.size() : QueryEnd) - Rest - 1);
                Rest = QueryEnd == std::string::npos ? Value.size() : QueryEnd;
            }

            Out.bHasFragment = Rest < Value.size() && Value[Rest] == '#';
            return Out;
        }

        std::optional<std::string> NormalizeOrigin(const std::string& Value)
        {
            const auto Parsed = Parse(Value);
            if (!Parsed || !Parsed->UserInfo.empty() || !(Parsed->Path.empty() || Parsed->Path == "/") ||
                Parsed->bHasQuery || Parsed->bHasFragment ||
                !(Parsed->Scheme == "https" || IsLoopbackHost(Parsed->Host)))
            {
                return std::nullopt;
            }

            return Parsed->Origin();
        }

        bool IsSameOrigin(const std::string& Value, const std::string& Origin)
        {
            const auto Parsed = Parse(Value);
            return Parsed && Parsed->UserInfo.empty() && Parsed->Origin() == Origin;
        }

        std::string Escape(const std::string& Value)
        {
            static const char HexDigits[] = "0123456789ABCDEF";
            std::string Out;
            Out.reserve(Value.size());
            for (const char Character : Value)
            {
                const auto Code = static_cast<unsigned char>(Character);
                const bool bUnreserved = (Code >= 'A' && Code <= 'Z') || (Code >= 'a' && Code <= 'z') ||
                                         (Code >= '0' && Code <= '9') || Code == '-' || Code == '.' || Code == '_' ||
                                         Code == '~';
                if (bUnreserved)
                {
                    Out.push_back(Character);
                }
                else
                {
                    Out.push_back('%');
                    Out.push_back(HexDigits[Code >> 4]);
                    Out.push_back(HexDigits[Code & 0xF]);
                }
            }

            return Out;
        }

        std::string FormEncode(const std::vector<std::pair<std::string, std::string>>& Fields)
        {
            std::string Out;
            for (const auto& Field : Fields)
            {
                if (!Out.empty())
                {
                    Out.push_back('&');
                }

                Out += Escape(Field.first) + "=" + Escape(Field.second);
            }

            return Out;
        }
    }
}
