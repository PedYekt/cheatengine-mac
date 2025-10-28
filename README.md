# CheatEngine - Educational Memory Management Tool for macOS

CheatEngine is an educational C++17 tool designed to demonstrate operating system memory management concepts through process introspection on macOS. It uses Mach kernel APIs to safely explore virtual memory, making it an excellent learning resource for understanding how modern operating systems manage memory.

## Educational Purpose

This tool is designed for:
- **Systems Programming Students** learning about virtual memory management
- **macOS Developers** understanding Mach kernel APIs and memory operations
- **Security Researchers** exploring process memory layout and protection mechanisms
- **Computer Science Educators** demonstrating OS concepts in practice

## Safety and Responsible Usage

**IMPORTANT**: CheatEngine is designed for educational purposes and should only be used on processes you own.

### Safety Guidelines
- **Only attach to your own processes** - Never attempt to access processes owned by other users
- **Respect system boundaries** - Do not attempt to bypass macOS security features
- **Use for learning** - This tool is meant to understand concepts, not to circumvent application security
- **Test safely** - Always test on sample applications or your own code first

### Legal and Ethical Considerations
- Only use on systems and processes you have explicit permission to analyze
- Respect software licenses and terms of service
- Do not use for malicious purposes or to gain unauthorized access
- Follow your organization's security policies and guidelines

## Installation and Compilation

### Prerequisites

1. **macOS Development Environment**:
   ```bash
   # Install Xcode Command Line Tools
   xcode-select --install
   ```

2. **CMake** (version 3.15 or higher):
   ```bash
   # Using Homebrew
   brew install cmake
   
   # Or using MacPorts
   sudo port install cmake
   ```

3. **Apple Developer Account** (for code signing):
   - Free Apple ID is sufficient for local development
   - Required for proper entitlements and debugging access

### Building CheatEngine

1. **Clone and prepare the project**:
   ```bash
   git clone <repository-url>
   cd cheatengine
   mkdir build && cd build
   ```

2. **Configure with CMake**:
   ```bash
   # For development builds with debugging
   cmake -DCMAKE_BUILD_TYPE=Debug ..
   
   # For optimized release builds
   cmake -DCMAKE_BUILD_TYPE=Release ..
   ```

3. **Build the project**:
   ```bash
   make -j$(sysctl -n hw.ncpu)
   ```

4. **Code Signing** (Essential for macOS):
   ```bash
   # The build system will automatically code sign with your development certificate
   # Ensure you have a valid Apple Developer certificate installed
   ```

### Troubleshooting Build Issues

**Missing Development Certificate**:
```bash
# Check available certificates
security find-identity -v -p codesigning

# If no certificates found, create one in Xcode:
# Xcode → Preferences → Accounts → Manage Certificates → + → Apple Development
```

**CMake Configuration Issues**:
```bash
# Clear build cache and reconfigure
rm -rf build/
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
```

## macOS Security Requirements

CheatEngine requires specific permissions to function on macOS due to Apple's security model.

### Required Entitlements

The application needs these entitlements (automatically configured during build):

```xml
<!-- Allow debugging access to processes -->
<key>com.apple.security.get-task-allow</key>
<true/>

<!-- Enable process debugging capabilities -->
<key>com.apple.security.cs.debugger</key>
<true/>

<!-- Disable library validation for development -->
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
```

### System Integrity Protection (SIP)

**What is SIP?**
System Integrity Protection is Apple's security feature that prevents modification of system files and processes, even by the root user.

**How it affects CheatEngine**:
- Cannot attach to system processes (kernel, launchd, etc.)
- Cannot access SIP-protected applications
- Limited to user-owned processes only

**Working with SIP**:
```bash
# Check SIP status
csrutil status

# SIP should remain ENABLED for security
# CheatEngine works within SIP constraints
```

### Code Signing Requirements

**Why Code Signing is Required**:
- macOS requires signed applications to use debugging APIs
- Entitlements are embedded in the code signature
- Unsigned binaries cannot use `task_for_pid`

**Development Signing**:
```bash
# Verify your application is properly signed
codesign -dv --entitlements - ./cheatengine

# Should show the required entitlements
```

## Usage Guide

### Basic Usage

1. **Start CheatEngine**:
   ```bash
   ./cheatengine
   ```

2. **Attach to a Process**:
   ```
   CheatEngine> attach <process_id>
   ```

3. **Explore Memory Regions**:
   ```
   CheatEngine> regions
   ```

4. **Search for Values**:
   ```
   CheatEngine> search 42        # Search for integer 42
   CheatEngine> search 3.14159   # Search for float value
   ```

5. **Monitor Memory Changes**:
   ```
   CheatEngine> monitor 0x1234567890  # Monitor specific address
   CheatEngine> watch                 # View monitored addresses
   ```

### Example Workflow

**Analyzing a Simple Program**:

1. **Create a test target**:
   ```cpp
   // test_program.cpp
   #include <iostream>
   #include <thread>
   #include <chrono>
   
   int main() {
       int counter = 0;
       while (true) {
           std::cout << "Counter: " << counter << std::endl;
           counter++;
           std::this_thread::sleep_for(std::chrono::seconds(2));
       }
   }
   ```

2. **Compile and run**:
   ```bash
   g++ -o test_program test_program.cpp
   ./test_program &
   echo $!  # Note the process ID
   ```

3. **Analyze with CheatEngine**:
   ```bash
   ./cheatengine
   > attach 12345  # Use actual PID
   > search 0      # Find counter when it's 0
   > # Wait for counter to increment
   > search 1      # Narrow down to addresses that changed
   > monitor 0x... # Monitor the counter variable
   ```

## Memory Management Concepts Demonstrated

### Virtual Memory Layout

CheatEngine helps visualize how macOS organizes process memory:

```
High Addresses
┌─────────────────┐
│     Stack       │ ← Function calls, local variables
├─────────────────┤
│       ↓         │
│                 │
│   Free Space    │
│                 │
│       ↑         │
├─────────────────┤
│     Heap        │ ← Dynamic allocations (malloc, new)
├─────────────────┤
│     Data        │ ← Global/static variables
├─────────────────┤
│     Text        │ ← Program code
└─────────────────┘
Low Addresses
```

### Memory Protection Flags

Understanding memory permissions:

- **Read (R)**: Can read data from this region
- **Write (W)**: Can modify data in this region  
- **Execute (X)**: Can execute code from this region

Common combinations:
- `R--`: Read-only data (constants, strings)
- `RW-`: Read-write data (variables, heap)
- `R-X`: Executable code (program text, libraries)
- `---`: No access (guard pages, unmapped regions)

### Mach Virtual Memory APIs

CheatEngine demonstrates these key macOS APIs:

1. **`task_for_pid()`**: Obtain task port for process access
2. **`mach_vm_region()`**: Enumerate memory regions
3. **`mach_vm_read_overwrite()`**: Read process memory
4. **`mach_vm_write()`**: Write to process memory

### CPU Cache and Memory Locality

The tool demonstrates:
- **Spatial Locality**: Accessing nearby memory addresses
- **Temporal Locality**: Accessing recently used memory
- **Cache Line Effects**: How CPU caches optimize memory access

## Troubleshooting

### Common Issues and Solutions

**"Operation not permitted" when attaching**:
```bash
# Check if process is owned by you
ps -o pid,user,comm -p <PID>

# Verify code signing
codesign -dv ./cheatengine

# Check entitlements
codesign -d --entitlements - ./cheatengine
```

**"Task for PID failed" errors**:
1. **Missing Entitlements**: Rebuild with proper code signing
2. **SIP Protection**: Target process may be system-protected
3. **Process Ownership**: Can only attach to your own processes
4. **Sandboxing**: Some sandboxed apps restrict access

**Build failures**:
```bash
# Clean and rebuild
make clean
cmake --build . --config Debug

# Check compiler version
clang++ --version  # Should be recent version

# Verify CMake configuration
cmake -LA | grep CMAKE_
```

### Security Error Explanations

**Missing `com.apple.security.get-task-allow`**:
- This entitlement is required for `task_for_pid()` access
- Must be embedded during code signing
- Rebuild the project to apply entitlements

**System Integrity Protection Blocks**:
- SIP prevents access to system processes
- This is normal and expected behavior
- Focus on user processes for learning

**Code Signature Invalid**:
```bash
# Re-sign the binary
codesign --force --sign "Apple Development" \
         --entitlements debug-entitlements.plist \
         ./cheatengine
```

### Getting Help

**Debug Mode**:
```bash
# Run with verbose output
./cheatengine --verbose

# Check system logs
log show --predicate 'process == "cheatengine"' --last 1h
```

**Reporting Issues**:
When reporting problems, include:
- macOS version (`sw_vers`)
- Xcode version (`xcodebuild -version`)
- Error messages and logs
- Steps to reproduce

## Educational Resources

### Recommended Reading

1. **"Mac OS X Internals" by Amit Singh** - Deep dive into macOS architecture
2. **"The Design and Implementation of the FreeBSD Operating System"** - Unix/BSD concepts
3. **Apple Developer Documentation** - Mach kernel and virtual memory APIs
4. **"Computer Systems: A Programmer's Perspective"** - Memory hierarchy and virtual memory

### Online Resources

- [Apple Developer Documentation](https://developer.apple.com/documentation/)
- [Mach Overview](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/KernelProgramming/Mach/Mach.html)
- [Virtual Memory Programming Guide](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/ManagingMemory/)

### Hands-On Exercises

1. **Memory Layout Exploration**:
   - Compile programs with different optimization levels
   - Observe how memory layout changes
   - Compare stack vs heap allocation patterns

2. **Security Boundary Testing**:
   - Try attaching to different types of processes
   - Understand when and why access is denied
   - Learn about macOS security model

3. **Performance Analysis**:
   - Measure memory access patterns
   - Observe cache effects in real programs
   - Understand memory bandwidth limitations

## Contributing

CheatEngine is an educational project. Contributions that enhance learning are welcome:

- **Documentation improvements**
- **Additional educational examples**
- **Better error explanations**
- **Cross-platform compatibility** (Linux, Windows)

### Development Guidelines

- Maintain educational focus
- Include comprehensive comments
- Add safety checks and validations
- Follow C++17 best practices
- Ensure cross-platform compatibility where possible

## License

This project is released under the MIT License. See LICENSE file for details.

## Acknowledgments

- Apple Developer Documentation for Mach VM APIs
- macOS security model documentation
- Educational resources from various computer science programs
- Open source memory analysis tools for inspiration

---

**Remember**: Use CheatEngine responsibly and only for educational purposes. Always respect system security boundaries and only analyze processes you own.