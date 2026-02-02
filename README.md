# CheatEngine - Memory Analysis Tool for macOS

CheatEngine is a C++17 tool for macOS process introspection and memory analysis. It uses Mach kernel APIs to explore virtual memory while respecting system security boundaries.

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


## License

This project is released under the MIT License. See LICENSE file for details.
