# ood_proxy_win_client

This project builds a **Windows-only GUI client** for launching secure RDP or VNC sessions. It uses Windows Forms and targets Windows 64-bit, but can be **cross-compiled on Linux** using the .NET SDK. No root privileges are needed.

---

## 🚀 Quick Start (Cross-Compiling on Linux)

### ✅ Install .NET SDK as an Unprivileged User

If your system does **not** have a `dotnet` module available, you can install it locally:

```bash
# 1. Choose a local install path
export DOTNET_ROOT=$HOME/dotnet
export PATH=$DOTNET_ROOT:$PATH

# 2. Download and install .NET SDK locally
wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh
chmod +x dotnet-install.sh
./dotnet-install.sh --install-dir "$DOTNET_ROOT" --channel 8.0

# 3. (Optional) Make it persistent
echo 'export DOTNET_ROOT=$HOME/dotnet' >> ~/.bashrc
echo 'export PATH=$DOTNET_ROOT:$PATH' >> ~/.bashrc
source ~/.bashrc
```

Verify your installation:

```bash
dotnet --info
```

Make sure `.NET 8.x` is shown and that you see `RID: win-x64` or similar.

---

## 🧪 Hello World: First Test Project (Optional but Recommended)

If you're new to C#, try this minimal example to ensure your toolchain is working:

### Step-by-Step: Build a "Hello World" Windows `.exe`

```bash
# 1. Create the project
dotnet new console -n HelloWorldTest
cd HelloWorldTest
```

You’ll see:

```
HelloWorldTest/
├── HelloWorldTest.csproj
└── Program.cs
```

Optionally edit `Program.cs` (though it already contains the correct code):

```csharp
using System;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Hello, world!");
    }
}
```

```bash
# 2. Build for Windows
dotnet publish -c Release -r win-x64 --self-contained true \
  /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true
```

```bash
# 3. Locate the .exe
ls bin/Release/net8.0/win-x64/publish/HelloWorldTest.exe
```

You can now transfer the `.exe` to a Windows system and run it. It should print:

```
Hello, world!
```

---

## 🧰 Build Instructions for This Project

### Step 1: Clone the Repository

```bash
git clone https://github.com/BYUHPC/oodproxy.git
cd <repo folder>/client/windows/source/csharp/ 
```

### Step 2: Create a New Windows Forms Project

```bash
dotnet new winforms -n ood_proxy_win_client
cd ood_proxy_win_client
```

### Step 3: Replace the Project Files

Copy in the provided source files:

```bash
cp ../Program.cs .
cp ../ood_proxy_win_client.csproj .
cp ../build.sh .
chmod +x build.sh
```

> Adjust `..` as needed if files are located elsewhere.

### Step 4: Build the Executable

Run the build script:

```bash
./build.sh
```

---

## 📦 Output Location

After building, your Windows executable will be located at:

```
bin/Release/net8.0-windows/win-x64/publish/ood_proxy_win_client.exe
```

Transfer this file to a Windows machine and double-click or run it from a terminal.

---

## ❓ Troubleshooting

If `dotnet publish` fails, try the following:

```bash
dotnet restore
dotnet build -c Release
dotnet publish -c Release -r win-x64 --self-contained true
```

Make sure:

- You're using **.NET SDK 8.0+**
- You're targeting `RuntimeIdentifier: win-x64`

---

## ⚠️ Notes

- This application uses Windows-only APIs like `System.Windows.Forms`, `mstsc.exe`, and `cmdkey`.  
  **It will not run on Linux — only on Windows.**
- The Linux build process is used only to generate `.exe` files that can be copied to a Windows system.

