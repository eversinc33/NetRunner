<p align="center">
  <img src="https://img.shields.io/badge/.NET-blueviolet" />
  <img src="https://img.shields.io/badge/Malware%20Analysis-orange" />
</p>

<p align="center">
  <img src="assets/top.png" alt="Banner" width="50%">
</p>

# ⚡ NetRunner

A .NET assembly tracer using [Harmony](https://github.com/pardeike/Harmony) for runtime method interception.

## Features

- Runtime method tracing
- Automatically traces all local assembly methods, supports external/referenced methods through a config file
- Logging of method calls, returns, arguments and return values
- Dumps reflectively loaded assemblies for analysis
- Optional stack trace logging

## Assembly Dumping

NetRunner automatically intercepts `Assembly.Load` calls and saves any assemblies loaded from byte arrays to disk, e.g. for easy unpacking. The dumped assemblies are saved in the current directory with a filename based on the SHA1 hash.

## Usage

```
NetRunner.exe [--methods methodsFile.txt] [--log logFile.log] [--stack] assembly.dll [Namespace.Class::Method]
```

Options:
- `--methods file.txt`: Optional file containing additional methods to trace
- `--log file.log`: Optional custom log file path (default: `./tracer.log`)
- `--stack`: Enable stack trace logging for each method call
- `assembly.dll`: Target assembly to analyze
- `--no-locals`: Do not patch local methods in the target assembly
- `--no-references`: Do not patch referenced external methods
- `Namespace.Class::Method`: Entry point method to invoke (optional)

### Methods File Format

Create a text file with one method per line in the format:
```python
System.Environment::GetFolderPath
System.IO.Directory::GetFiles
System.IO.Directory::GetDirectories
System.IO.File::Delete
System.IO.Stream::Read
# reflection
System.Reflection.Assembly::Load
```

Be careful hooking methods that are used by the tracer itself as that can result in deadly recursion loops.
Lines starting with `#` are treated as comments and ignored.

An example configuration file can be found at [./Methods.txt](./Methods.txt).

## Development

### Windows

Just use the `.sln` file in Visual Studio.

### Debian

```bash
# Install Mono
sudo apt install mono-complete nuget  

# Build the project
nuget restore NetRunner.sln
xbuild /p:Configuration=Release NetRunner.sln
```
