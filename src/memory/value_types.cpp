#include "cheatengine/memory/value_types.hpp"
#include <stdexcept>

namespace cheatengine {

SearchValue SearchValue::fromInt32(std::int32_t value)
{
    SearchValue sv;
    sv.type_ = ValueType::INT32;
    sv.data_ = toBytes(value);
    return sv;
}

SearchValue SearchValue::fromInt64(std::int64_t value)
{
    SearchValue sv;
    sv.type_ = ValueType::INT64;
    sv.data_ = toBytes(value);
    return sv;
}

SearchValue SearchValue::fromFloat32(float value)
{
    SearchValue sv;
    sv.type_ = ValueType::FLOAT32;
    sv.data_ = toBytes(value);
    return sv;
}

SearchValue SearchValue::fromFloat64(double value)
{
    SearchValue sv;
    sv.type_ = ValueType::FLOAT64;
    sv.data_ = toBytes(value);
    return sv;
}

SearchValue SearchValue::fromBytes(const std::vector<std::uint8_t>& bytes)
{
    SearchValue sv;
    sv.type_ = ValueType::BYTES;
    sv.data_ = bytes;
    return sv;
}

std::int32_t SearchValue::toInt32() const
{
    if (type_ != ValueType::INT32) throw std::runtime_error("Not INT32");
    std::int32_t value;
    std::memcpy(&value, data_.data(), sizeof(value));
    return value;
}

std::int64_t SearchValue::toInt64() const
{
    if (type_ != ValueType::INT64) throw std::runtime_error("Not INT64");
    std::int64_t value;
    std::memcpy(&value, data_.data(), sizeof(value));
    return value;
}

float SearchValue::toFloat32() const
{
    if (type_ != ValueType::FLOAT32) throw std::runtime_error("Not FLOAT32");
    float value;
    std::memcpy(&value, data_.data(), sizeof(value));
    return value;
}

double SearchValue::toFloat64() const
{
    if (type_ != ValueType::FLOAT64) throw std::runtime_error("Not FLOAT64");
    double value;
    std::memcpy(&value, data_.data(), sizeof(value));
    return value;
}

} // namespace cheatengine
