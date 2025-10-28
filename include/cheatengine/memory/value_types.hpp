/**
 * @file value_types.hpp
 * @brief Type-safe value representation for memory searching
 * 
 * This file demonstrates how to build type-safe interfaces for memory operations
 * while providing educational insight into data representation, endianness,
 * and type conversion concepts.
 * 
 * Educational Focus:
 * - Binary data representation and type conversion
 * - Template metaprogramming for type safety
 * - Memory layout of different data types
 * - Endianness and cross-platform considerations
 */

#pragma once

#include <cstdint>
#include <cstring>
#include <type_traits>
#include <vector>

namespace cheatengine {

/**
 * @brief Supported value types for memory searching
 * 
 * These types represent the most common data types found in applications,
 * demonstrating different memory representations and sizes.
 */
enum class ValueType {
    INT32,      ///< 32-bit signed integer (4 bytes)
    INT64,      ///< 64-bit signed integer (8 bytes)  
    FLOAT32,    ///< 32-bit IEEE 754 floating point (4 bytes)
    FLOAT64,    ///< 64-bit IEEE 754 floating point (8 bytes)
    BYTES       ///< Raw byte sequence (variable length)
};

/**
 * @brief Type-safe container for values to search in memory
 * 
 * The SearchValue class demonstrates how to build type-safe interfaces that
 * preserve type information while working with binary data. It showcases
 * template metaprogramming and provides educational insight into data
 * representation concepts.
 * 
 * Educational Concepts Demonstrated:
 * - Type-safe binary data handling
 * - Template metaprogramming with SFINAE
 * - Data type size and alignment considerations
 * - Memory representation of different data types
 * - Endianness and platform-specific considerations
 * 
 * Design Principles:
 * - Type safety: Prevents mixing incompatible data types
 * - Memory efficiency: Stores data in compact binary format
 * - Educational value: Exposes underlying data representation
 * - Extensibility: Easy to add new data types
 */
class SearchValue {
public:
    /**
     * @brief Get the type of value stored
     * @return ValueType The type category of this value
     */
    ValueType type() const noexcept { return type_; }
    
    /**
     * @brief Get the raw binary data
     * @return const std::vector<std::uint8_t>& Binary representation of the value
     * 
     * Provides access to the underlying binary representation, useful for
     * educational analysis of how different data types are stored in memory.
     */
    const std::vector<std::uint8_t>& data() const noexcept { return data_; }

    // Factory methods for creating SearchValues - demonstrate type-safe construction
    
    /**
     * @brief Create SearchValue from 32-bit signed integer
     * @param value Integer value to store
     * @return SearchValue Type-safe container for the integer
     * 
     * Demonstrates how 32-bit integers are represented in memory and
     * provides insight into integer storage formats.
     */
    static SearchValue fromInt32(std::int32_t value);
    
    /**
     * @brief Create SearchValue from 64-bit signed integer
     * @param value Integer value to store
     * @return SearchValue Type-safe container for the integer
     * 
     * Shows the difference between 32-bit and 64-bit integer representation
     * and demonstrates how larger data types affect memory usage.
     */
    static SearchValue fromInt64(std::int64_t value);
    
    /**
     * @brief Create SearchValue from 32-bit floating point
     * @param value Float value to store
     * @return SearchValue Type-safe container for the float
     * 
     * Demonstrates IEEE 754 floating-point representation and shows how
     * floating-point numbers are stored in binary format.
     */
    static SearchValue fromFloat32(float value);
    
    /**
     * @brief Create SearchValue from 64-bit floating point
     * @param value Double value to store
     * @return SearchValue Type-safe container for the double
     * 
     * Shows double-precision floating-point representation and demonstrates
     * the trade-offs between precision and memory usage.
     */
    static SearchValue fromFloat64(double value);
    
    /**
     * @brief Create SearchValue from raw byte sequence
     * @param bytes Raw binary data to store
     * @return SearchValue Type-safe container for the bytes
     * 
     * Allows searching for arbitrary byte patterns, useful for finding
     * complex data structures or specific binary signatures.
     */
    static SearchValue fromBytes(const std::vector<std::uint8_t>& bytes);

    // Conversion utilities for extracting values from SearchValue
    
    /**
     * @brief Extract value as 32-bit signed integer
     * @return std::int32_t The stored integer value
     * @throws CheatEngineException if stored type is not INT32
     * 
     * Demonstrates type-safe value extraction with runtime type checking.
     * Educational Note: Shows how to safely convert binary data back to
     * typed values while preserving type safety.
     */
    std::int32_t toInt32() const;
    
    /**
     * @brief Extract value as 64-bit signed integer
     * @return std::int64_t The stored integer value
     * @throws CheatEngineException if stored type is not INT64
     */
    std::int64_t toInt64() const;
    
    /**
     * @brief Extract value as 32-bit floating point
     * @return float The stored float value
     * @throws CheatEngineException if stored type is not FLOAT32
     */
    float toFloat32() const;
    
    /**
     * @brief Extract value as 64-bit floating point
     * @return double The stored double value
     * @throws CheatEngineException if stored type is not FLOAT64
     */
    double toFloat64() const;
    
    /**
     * @brief Template-based value extraction with compile-time type checking
     * @tparam T Type to extract (must match stored type)
     * @return T The stored value converted to requested type
     * 
     * This template demonstrates advanced C++17 features including constexpr if
     * and SFINAE for compile-time type checking and conversion.
     * 
     * Educational Concepts:
     * - Template metaprogramming with constexpr if
     * - Compile-time type checking and validation
     * - SFINAE (Substitution Failure Is Not An Error) patterns
     * - Type trait usage for generic programming
     */
    template <typename T>
    T getValue() const
    {
        if constexpr (std::is_same_v<T, std::int32_t>) {
            return toInt32();
        } else if constexpr (std::is_same_v<T, std::int64_t>) {
            return toInt64();
        } else if constexpr (std::is_same_v<T, float>) {
            return toFloat32();
        } else if constexpr (std::is_same_v<T, double>) {
            return toFloat64();
        } else {
            static_assert(always_false<T>::value, "Unsupported type for SearchValue::getValue");
        }
    }

    /**
     * @brief Template factory method for creating SearchValues from any supported type
     * @tparam T Type of value to store (automatically deduced)
     * @param value Value to store in the SearchValue
     * @return SearchValue Type-safe container for the value
     * 
     * This template demonstrates advanced metaprogramming techniques for
     * automatic type deduction and size-based type selection.
     * 
     * Educational Concepts:
     * - Template argument deduction
     * - Type traits for compile-time type analysis
     * - Size-based type selection using sizeof
     * - Constexpr if for conditional compilation
     * - SFINAE for unsupported type handling
     * 
     * Usage Examples:
     * @code
     * auto int_val = SearchValue::create(42);        // Creates INT32
     * auto long_val = SearchValue::create(42L);      // Creates INT64  
     * auto float_val = SearchValue::create(3.14f);   // Creates FLOAT32
     * auto double_val = SearchValue::create(3.14);   // Creates FLOAT64
     * @endcode
     */
    template <typename T>
    static SearchValue create(T value)
    {
        if constexpr (std::is_integral_v<T>) {
            if constexpr (sizeof(T) == sizeof(std::int32_t)) {
                return fromInt32(static_cast<std::int32_t>(value));
            } else if constexpr (sizeof(T) == sizeof(std::int64_t)) {
                return fromInt64(static_cast<std::int64_t>(value));
            } else {
                static_assert(always_false<T>::value, "Unsupported integral size for SearchValue::create");
            }
        } else if constexpr (std::is_floating_point_v<T>) {
            if constexpr (sizeof(T) == sizeof(float)) {
                return fromFloat32(static_cast<float>(value));
            } else if constexpr (sizeof(T) == sizeof(double)) {
                return fromFloat64(static_cast<double>(value));
            } else {
                static_assert(always_false<T>::value, "Unsupported floating-point size for SearchValue::create");
            }
        } else {
            static_assert(always_false<T>::value, "Unsupported type for SearchValue::create");
        }
    }

private:
    /**
     * @brief Helper template for static_assert in template contexts
     * 
     * This is a common C++ metaprogramming idiom for generating compile-time
     * errors in template contexts where direct static_assert(false) would
     * always trigger, even for unused template instantiations.
     */
    template <typename>
    struct always_false : std::false_type {
    };

    /**
     * @brief Convert typed value to binary representation
     * @tparam T Type of value to convert
     * @param value Value to convert to bytes
     * @return std::vector<std::uint8_t> Binary representation of the value
     * 
     * This template demonstrates how to convert typed values to their binary
     * representation using memcpy, showing the underlying memory layout.
     * 
     * Educational Note: This function reveals how different data types are
     * stored in memory and demonstrates the concept of type punning through
     * byte-level access.
     */
    template <typename T>
    static std::vector<std::uint8_t> toBytes(const T& value)
    {
        std::vector<std::uint8_t> bytes(sizeof(T));
        std::memcpy(bytes.data(), &value, sizeof(T));
        return bytes;
    }

    ValueType type_{ValueType::BYTES};          ///< Type category of stored value
    std::vector<std::uint8_t> data_;           ///< Binary representation of the value
};

} // namespace cheatengine
