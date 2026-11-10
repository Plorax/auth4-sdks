// URL helpers for the auth origin: origin normalization, same-origin checks and form encoding.
#pragma once

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace Auth4
{
    namespace Url
    {
        struct Parts
        {
            std::string Scheme;
            std::string UserInfo;
            std::string Host;
            std::string Port;
            std::string Path;
            bool bHasQuery = false;
            std::string Query;
            bool bHasFragment = false;

            /// scheme://host[:port], lowercased, without a default port.
            std::string Origin() const;
        };

        /// Parses an absolute http or https URL. Returns nothing for anything else.
        std::optional<Parts> Parse(const std::string& Value);

        /// https origin without a path; plain http only for loopback hosts. Nothing when invalid.
        std::optional<std::string> NormalizeOrigin(const std::string& Value);

        /// True when Value is an absolute URL on exactly this origin.
        bool IsSameOrigin(const std::string& Value, const std::string& Origin);

        /// Percent-encodes everything except RFC 3986 unreserved characters.
        std::string Escape(const std::string& Value);

        /// application/x-www-form-urlencoded body.
        std::string FormEncode(const std::vector<std::pair<std::string, std::string>>& Fields);
    }
}
