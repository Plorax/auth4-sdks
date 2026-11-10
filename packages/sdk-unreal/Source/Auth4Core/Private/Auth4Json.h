// Minimal JSON for the auth4.dev wire shapes: objects of strings, numbers, booleans and nested
// objects. Arrays are parsed and skipped. Numbers are parsed without the C locale.
#pragma once

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace Auth4
{
    namespace Json
    {
        struct Object;

        struct Field
        {
            enum class Type
            {
                Null,
                String,
                Number,
                Bool,
                Object,
                Array,
            };

            Type Kind = Type::Null;
            std::string Text;
            double Number = 0;
            bool Flag = false;
            std::shared_ptr<Object> Child;
        };

        struct Object
        {
            std::map<std::string, Field> Fields;
        };

        /// Parses a top-level object. Returns null for anything else or for malformed input.
        std::shared_ptr<Object> ParseObject(const std::string& Text);

        /// The string at Key, or nothing when absent or not a string.
        std::optional<std::string> GetString(const Object* Value, const std::string& Key);

        /// The number at Key, or nothing when absent or not a number.
        std::optional<double> GetNumber(const Object* Value, const std::string& Key);

        /// The object at Key, or null.
        const Object* GetObject(const Object* Value, const std::string& Key);

        /// Serializes a flat object of string values, in the given order.
        std::string SerializeStrings(const std::vector<std::pair<std::string, std::string>>& Values);
    }
}
