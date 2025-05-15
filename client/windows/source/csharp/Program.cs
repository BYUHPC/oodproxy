// Final version of Program.cs with user-facing MessageBox error handling
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

class Program
{
    static string tempDir;
    static Process stunnelProcess;
    static string credentialTarget;
    static string pidFilePath;
    static bool isDebug = false;

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern bool AllocConsole();

    static int Main(string[] args)
    {
        if (args.Contains("--debug"))
        {
            AllocConsole();
            isDebug = true;
        }

        string configPath = args.FirstOrDefault(arg => !arg.StartsWith("--"));
        if (string.IsNullOrWhiteSpace(configPath))
        {
            MessageBox.Show("No configuration file was specified.", "Missing Configuration", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }

        try
        {
            Log("Starting OOD Proxy Client");
            CleanupOrphanedStunnelProcesses();
            var config = ParseConfigFile(configPath);
            tempDir = InitializeTempDirectory();
            var certPaths = InitializeCertificates(config, tempDir);
            int localPort = StartStunnelProxy(config, certPaths);

            Log("Waiting for stunnel to open port...");
            if (!WaitForPortReady(localPort, 5000))
            {
                MessageBox.Show("Stunnel did not open the local port in time.", "Stunnel Timeout", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return 1;
            }
            Log("Stunnel port is ready.");

            if (config.TryGetValue("PROTO", out string proto))
            {
                if (proto.Equals("rdp", StringComparison.OrdinalIgnoreCase))
                {
                    SetRdpCredentials(config);
                    StartRdpSession(localPort, config);
                }
                else if (proto.Equals("vnc", StringComparison.OrdinalIgnoreCase))
                {
                    StartVncSession(localPort, config);
                }
                else
                {
                    MessageBox.Show($"Unsupported protocol specified: {proto}\nOnly 'rdp' and 'vnc' are supported.", "Unsupported Protocol", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return 1;
                }
            }
            else
            {
                MessageBox.Show("The configuration file is missing the 'PROTO' field.", "Missing Protocol", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return 1;
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
        finally
        {
            Cleanup();
            Log("Cleanup complete. Exiting.");
        }

        return 0;
    }

    static void Log(string message)
    {
        if (isDebug)
            Console.WriteLine($"[LOG {DateTime.Now:HH:mm:ss}] {message}");
    }

    static Dictionary<string, string> ParseConfigFile(string path)
    {
        if (!File.Exists(path))
        {
            MessageBox.Show($"The specified configuration file could not be found:\n{path}", "File Not Found", MessageBoxButtons.OK, MessageBoxIcon.Error);
            Environment.Exit(1);
        }

        var config = new Dictionary<string, string>();
        foreach (var line in File.ReadLines(path))
        {
            var match = Regex.Match(line, "^([^=]+)=(.*)$");
            if (match.Success)
                config[match.Groups[1].Value.Trim()] = match.Groups[2].Value.Trim();
        }

        string[] requiredFields = { "REMOTE_PROXY", "CRT_BASE64", "KEY_BASE64", "CACRT_BASE64", "PROTO" };
        foreach (var field in requiredFields)
        {
            if (!config.ContainsKey(field) || string.IsNullOrWhiteSpace(config[field]))
            {
                MessageBox.Show($"Configuration error: '{field}' is missing or empty.", "Invalid Configuration", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Environment.Exit(1);
            }
        }

        if (config["PROTO"].Equals("rdp", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var field in new[] { "USERNAME", "PASSWORD" })
            {
                if (!config.ContainsKey(field) || string.IsNullOrWhiteSpace(config[field]))
                {
                    MessageBox.Show($"Configuration error: '{field}' is required for RDP connections.", "Invalid Configuration", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    Environment.Exit(1);
                }
            }
        }
        else if (config["PROTO"].Equals("vnc", StringComparison.OrdinalIgnoreCase))
        {
            if (!config.ContainsKey("PASSWORD") || string.IsNullOrWhiteSpace(config["PASSWORD"]))
            {
                MessageBox.Show("Configuration error: 'PASSWORD' is required for VNC connections.", "Invalid Configuration", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Environment.Exit(1);
            }
        }

        Log("Config file parsed successfully.");
        return config;
    }

    static string InitializeTempDirectory()
    {
        string dir = Path.Combine(Path.GetTempPath(), "stunnel-" + Path.GetRandomFileName());
        Directory.CreateDirectory(dir);
        Log($"Created temporary directory: {dir}");
        return dir;
    }

    static (string CertPath, string KeyPath, string CAPath) InitializeCertificates(Dictionary<string, string> config, string tempDir)
    {
        string certPath = Path.Combine(tempDir, "cert.pem");
        string keyPath = Path.Combine(tempDir, "key.pem");
        string caPath = Path.Combine(tempDir, "ca.pem");

        File.WriteAllBytes(certPath, Convert.FromBase64String(config["CRT_BASE64"]));
        File.WriteAllBytes(keyPath, Convert.FromBase64String(config["KEY_BASE64"]));
        File.WriteAllBytes(caPath, Convert.FromBase64String(config["CACRT_BASE64"]));

        Log("Certificates decoded and written to temp files.");
        return (certPath, keyPath, caPath);
    }

    static void CleanupOrphanedStunnelProcesses()
    {
        string tempDir = Path.GetTempPath();
        var pidFiles = Directory.GetFiles(tempDir, "stunnel-rdp-proxy-*.pid");
        foreach (var pidFile in pidFiles)
        {
            if (int.TryParse(File.ReadAllText(pidFile), out int pid))
            {
                try
                {
                    var proc = Process.GetProcessById(pid);
                    if (proc.ProcessName.Equals("stunnel", StringComparison.OrdinalIgnoreCase))
                    {
                        Log($"Killing orphaned stunnel process (PID: {pid})");
                        proc.Kill();
                    }
                }
                catch { }
            }
            File.Delete(pidFile);
        }
    }

    static int StartStunnelProxy(Dictionary<string, string> config, (string CertPath, string KeyPath, string CAPath) certPaths)
    {
        int localPort = new Random().Next(49152, 65535);
        Log($"Starting Stunnel proxy on 127.0.0.1:{localPort}...");

        string conf = $@"
[proxy]
client = yes
accept = 127.0.0.1:{localPort}
connect = {config["REMOTE_PROXY"]}
cert = {certPaths.CertPath}
key = {certPaths.KeyPath}
CAfile = {certPaths.CAPath}
verifyChain = yes
sslVersion = TLSv1.2
options = NO_SSLv3
options = NO_TLSv1
";

        string confPath = Path.Combine(tempDir, "stunnel.conf");
        File.WriteAllText(confPath, conf);

        string stunnelPath = FindStunnelExecutable();
        Log($"Launching Stunnel from: {stunnelPath}");

        stunnelProcess = Process.Start(new ProcessStartInfo
        {
            FileName = stunnelPath,
            Arguments = confPath,
            UseShellExecute = false,
            CreateNoWindow = true
        });

        if (stunnelProcess.HasExited)
            throw new Exception("Stunnel exited immediately");

        pidFilePath = Path.Combine(Path.GetTempPath(), $"stunnel-rdp-proxy-{stunnelProcess.Id}.pid");
        File.WriteAllText(pidFilePath, stunnelProcess.Id.ToString());

        return localPort;
    }

    static string FindStunnelExecutable()
    {
        string[] paths =
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "stunnel\\bin\\stunnel.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "stunnel\\bin\\stunnel.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs\\stunnel\\bin\\stunnel.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "stunnel\\bin\\stunnel.exe") // new user-scope path
        };

        foreach (var path in paths)
            if (File.Exists(path)) return path;

        throw new FileNotFoundException("Stunnel executable not found");
    }

    static void SetRdpCredentials(Dictionary<string, string> config)
    {
        credentialTarget = "TERMSRV/127.0.0.1";
        Log("Setting RDP credentials using cmdkey...");
        Process.Start(new ProcessStartInfo
        {
            FileName = "cmdkey",
            Arguments = $"/add:{credentialTarget} /user:{config["USERNAME"]} /pass:{config["PASSWORD"]}",
            UseShellExecute = false,
            CreateNoWindow = true
        })?.WaitForExit();
    }

    static void StartRdpSession(int localPort, Dictionary<string, string> config)
    {
        string fullscreen = (config.ContainsKey("FULLSCREEN") && config["FULLSCREEN"].Equals("true", StringComparison.OrdinalIgnoreCase)) ? "2" : "1";

        string rdpContent = $@"full address:s:127.0.0.1:{localPort}
username:s:{config["USERNAME"]}
authentication level:i:0
prompt for credentials:i:0
screen mode id:i:{fullscreen}
";

        string rdpPath = Path.Combine(tempDir, "session.rdp");
        File.WriteAllText(rdpPath, rdpContent);

        Log("Launching RDP session...");
        Process.Start("mstsc.exe", rdpPath)?.WaitForExit();
    }

    static void StartVncSession(int localPort, Dictionary<string, string> config)
    {
        string turboVncDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "TurboVNC");
        string javaExePath = Path.Combine(turboVncDir, "java", "jre", "bin", "javaw.exe");
        string vncJarPath = Path.Combine(turboVncDir, "java", "VncViewer.jar");

	if (!File.Exists(vncJarPath))
	{
	    Log("TurboVNC is not installed. VNC connections are not available.");
	    MessageBox.Show(
       		"TurboVNC is not installed.\n\n" +
	        "Please install it from:\nhttps://www.turbovnc.org/Downloads.html\n\n" +
	        "Until then, VNC connections cannot be used.",
	        "TurboVNC Not Found",
       		 MessageBoxButtons.OK,
	        MessageBoxIcon.Error
	    );
    	return;
	}

        var args = new List<string>
        {
            "-jar",
            $"\"{vncJarPath}\"",
            "-SecurityTypes", "VncAuth"
        };

        if (config.TryGetValue("PASSWORD", out string password) && !string.IsNullOrWhiteSpace(password))
        {
            args.Add("-Password");
            args.Add(password);
            Log("VNC password authentication configured");
        }
        else
        {
            Log("Warning: No VNC password provided - authentication may fail");
        }

        if (config.TryGetValue("FULLSCREEN", out string fullscreen) && fullscreen.Equals("true", StringComparison.OrdinalIgnoreCase))
        {
            args.Add("-Fullscreen");
            Log("VNC fullscreen mode enabled");
        }

        args.Add($"127.0.0.1::{localPort}");

        Log($"Launching TurboVNC: {javaExePath} {string.Join(" ", args)}");

        var proc = Process.Start(new ProcessStartInfo
        {
            FileName = javaExePath,
            Arguments = string.Join(" ", args),
            WorkingDirectory = turboVncDir,
            UseShellExecute = true
        });

        if (proc == null)
            throw new Exception("Failed to launch TurboVNC viewer.");

        Log("Waiting for TurboVNC viewer to exit...");
        proc.WaitForExit();
        Log("TurboVNC viewer has exited.");
    }

    static bool WaitForPortReady(int port, int timeoutMs = 5000)
    {
        var stopwatch = Stopwatch.StartNew();
        while (stopwatch.ElapsedMilliseconds < timeoutMs)
        {
            var netstat = Process.Start(new ProcessStartInfo
            {
                FileName = "netstat",
                Arguments = "-an",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });

            string output = netstat.StandardOutput.ReadToEnd();
            netstat.WaitForExit();

            if (output.Contains($"127.0.0.1:{port}"))
            {
                return true;
            }

            Thread.Sleep(100); // quick polling
        }
        return false;
    }


    static void Cleanup()
    {
        if (!string.IsNullOrEmpty(credentialTarget))
        {
            Log("Deleting RDP credentials...");
            Process.Start(new ProcessStartInfo
            {
                FileName = "cmdkey",
                Arguments = $"/delete:{credentialTarget}",
                UseShellExecute = false,
                CreateNoWindow = true
            })?.WaitForExit();
        }

        if (stunnelProcess != null && !stunnelProcess.HasExited)
        {
            Log("Killing Stunnel process...");
            stunnelProcess.Kill();
        }

        if (!string.IsNullOrEmpty(pidFilePath) && File.Exists(pidFilePath))
        {
            Log("Deleting PID file...");
            File.Delete(pidFilePath);
        }

        if (!string.IsNullOrEmpty(tempDir) && Directory.Exists(tempDir))
        {
            Log("Deleting temporary directory...");
            Directory.Delete(tempDir, true);
        }
    }
}
