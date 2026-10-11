#include "json.hpp"
#include <cassert>
#include <iostream>

using ps5nm::JsonValue;

int main() {
    // 1. Basic object parsing
    {
        JsonValue v;
        std::string err;
        assert(JsonValue::Parse(R"({"protocol": "nfs", "port": 2049, "enabled": true, "sub": null})", v, &err));
        assert(err.empty());
        assert(v.IsObject());
        assert(v.GetString("protocol") == "nfs");
        assert(v.GetInt("port") == 2049);
        assert(v["enabled"].bool_val == true);
        assert(v["sub"].IsNull());
    }

    // 2. Substring trap test
    {
        JsonValue v;
        std::string err;
        assert(JsonValue::Parse(R"({"summary": "protocol: nfs is fun", "protocol": "smb"})", v, &err));
        assert(err.empty());
        assert(v.GetString("protocol") == "smb");
    }

    // 3. String escaping and surrogates
    {
        JsonValue v;
        std::string err;
        assert(JsonValue::Parse(R"({"msg": "hello\nworld\t\"quoted\"\\slash\u0041\uD83D\uDE00"})", v, &err));
        assert(err.empty());
        assert(v.GetString("msg").find("hello\nworld\t\"quoted\"\\slashA") == 0);
    }

    // 4. Malformed syntax
    {
        JsonValue v;
        std::string err;
        assert(!JsonValue::Parse(R"({"unclosed": )", v, &err));
        assert(!err.empty());
    }

    // 5. Trailing garbage
    {
        JsonValue v;
        std::string err;
        assert(!JsonValue::Parse(R"({"protocol": "nfs"} trailing)", v, &err));
        assert(!err.empty());
    }

    // 6. Leading zeroes
    {
        JsonValue v;
        std::string err;
        assert(!JsonValue::Parse(R"({"num": 0123})", v, &err));
        assert(!err.empty());
    }

    std::cout << "All JsonValue unit tests passed.\n";
    return 0;
}
