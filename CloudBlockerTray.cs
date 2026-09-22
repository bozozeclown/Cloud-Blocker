using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Threading;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("Cloud Blocker Tray")]
[assembly: System.Reflection.AssemblyProduct("Cloud Blocker")]
[assembly: System.Reflection.AssemblyVersion("2.0.0.0")]
[assembly: System.Reflection.AssemblyFileVersion("2.0.0.0")]

namespace CloudBlockerTray
{
    internal static class Program
    {
        private const string StartupTaskName = "Cloud Blocker Tray";
        private static NotifyIcon _tray;
        private static ToolStripMenuItem _startupItem;
        private static string _appDir;
        private static string _enginePath;

        [STAThread]
        private static void Main(string[] args)
        {
            _appDir = Path.GetDirectoryName(Application.ExecutablePath);
            _enginePath = Path.Combine(_appDir, "Block-CloudIPs.ps1");

            // Headless self-test hook (used by the build/verification step).
            if (args.Length > 0 && args[0] == "--verify")
            {
                string outp = Path.Combine(Path.GetTempPath(), "cloudblocker_tray_verify.txt");
                try { File.WriteAllText(outp, "engine=" + _enginePath + "\r\n" + RunEngine("ALL", "Verify", "")); }
                catch (Exception ex) { File.WriteAllText(outp, "EXCEPTION: " + ex); }
                return;
            }

            bool createdNew;
            using (var mutex = new Mutex(true, "Global\\CloudBlockerTray_SingleInstance", out createdNew))
            {
                if (!createdNew) return;
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                BuildTray();
                Application.Run();
            }
        }

        private static void BuildTray()
        {
            var menu = new ContextMenuStrip();
            menu.Items.Add(new ToolStripMenuItem("Cloud Blocker") { Enabled = false });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(Item("Status / health check", delegate { ShowStatus(); }));
            menu.Items.Add(new ToolStripSeparator());

            var block = new ToolStripMenuItem("Block");
            block.DropDownItems.Add(Item("AWS", delegate { DoBlock("AWS", false); }));
            block.DropDownItems.Add(Item("GCP", delegate { DoBlock("GCP", false); }));
            block.DropDownItems.Add(Item("Azure", delegate { DoBlock("Azure", false); }));
            block.DropDownItems.Add(new ToolStripSeparator());
            block.DropDownItems.Add(Item("ALL  (force)", delegate { DoBlock("ALL", true); }));
            menu.Items.Add(block);

            var trial = new ToolStripMenuItem("Trial block (auto-unblock 15 min)");
            foreach (var p in new[] { "AWS", "GCP", "Azure", "ALL" })
            {
                string prov = p;
                trial.DropDownItems.Add(Item(prov, delegate { DoTrial(prov); }));
            }
            menu.Items.Add(trial);

            var unblock = new ToolStripMenuItem("Unblock");
            foreach (var p in new[] { "AWS", "GCP", "Azure", "ALL" })
            {
                string prov = p;
                unblock.DropDownItems.Add(Item(prov, delegate { DoUnblock(prov); }));
            }
            menu.Items.Add(unblock);

            menu.Items.Add(Item("PANIC: unblock everything", delegate { DoUnblock("ALL"); }));
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(Item("Open manager (PowerShell)", delegate { OpenManager(); }));
            menu.Items.Add(Item("Open program folder", delegate { OpenPath(_appDir); }));
            menu.Items.Add(Item("Open log file", delegate { OpenLog(); }));
            menu.Items.Add(Item("Open README", delegate { OpenPath(Path.Combine(_appDir, "README.md")); }));
            menu.Items.Add(new ToolStripSeparator());

            _startupItem = new ToolStripMenuItem("Run at startup");
            _startupItem.Click += delegate { ToggleStartup(); };
            menu.Items.Add(_startupItem);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(Item("Exit", delegate { _tray.Visible = false; Application.Exit(); }));

            _tray = new NotifyIcon();
            try { _tray.Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
            if (_tray.Icon == null) _tray.Icon = SystemIcons.Shield;
            _tray.Text = "Cloud Blocker";
            _tray.ContextMenuStrip = menu;
            _tray.Visible = true;
            _tray.DoubleClick += delegate { ShowStatus(); };

            UpdateStartupCheck();
        }

        private static ToolStripMenuItem Item(string text, EventHandler handler)
        {
            var it = new ToolStripMenuItem(text);
            it.Click += handler;
            return it;
        }

        // ----- engine invocation -------------------------------------------------

        private static string RunEngine(string provider, string action, string extra)
        {
            if (!File.Exists(_enginePath)) return "Engine not found:\r\n" + _enginePath;
            var psi = new ProcessStartInfo("powershell.exe",
                "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + _enginePath + "\" -Provider " +
                provider + " -Action " + action + extra);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            try
            {
                var p = Process.Start(psi);
                string o = p.StandardOutput.ReadToEnd();
                string e = p.StandardError.ReadToEnd();
                p.WaitForExit();
                string res = o;
                if (!string.IsNullOrEmpty(e)) res += (res.Length > 0 ? "\r\n" : "") + e;
                return res + "\r\n[exit " + p.ExitCode + "]";
            }
            catch (Exception ex)
            {
                return "Failed to run engine: " + ex.Message;
            }
        }

        private static void ShowStatus()
        {
            ThreadPool.QueueUserWorkItem(delegate
            {
                string r = RunEngine("ALL", "Verify", "");
                MessageBox.Show(r, "Cloud Blocker - Status", MessageBoxButtons.OK, MessageBoxIcon.Information);
            });
        }

        private static void DoBlock(string provider, bool force)
        {
            string msg = "Block all IPv4 ranges for " + provider + "?";
            if (provider == "ALL")
                msg = "Block AWS + GCP + Azure?\r\n\r\nThis is huge and WILL break services hosted on them. The engine checks connectivity and rolls back automatically if you get locked out.";
            if (MessageBox.Show(msg, "Cloud Blocker", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            RunActionAsync("Block " + provider, provider, "Block", force ? " -Force" : "");
        }

        private static void DoTrial(string provider)
        {
            string msg = "Trial-block " + provider + " with an automatic unblock after 15 minutes?\r\n\r\nIf it breaks things, it reverts on its own.";
            if (MessageBox.Show(msg, "Cloud Blocker", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            RunActionAsync("Trial block " + provider, provider, "Block", " -TrialMinutes 15");
        }

        private static void DoUnblock(string provider)
        {
            if (MessageBox.Show("Remove all cloud-block rules for " + provider + "?", "Cloud Blocker",
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            RunActionAsync("Unblock " + provider, provider, "Unblock", "");
        }

        private static void RunActionAsync(string title, string provider, string action, string extra)
        {
            _tray.ShowBalloonTip(3000, "Cloud Blocker", title + " started...", ToolTipIcon.Info);
            ThreadPool.QueueUserWorkItem(delegate
            {
                string r = RunEngine(provider, action, extra);
                _tray.ShowBalloonTip(4000, "Cloud Blocker", title + " finished.", ToolTipIcon.Info);
                MessageBox.Show(r, title, MessageBoxButtons.OK, MessageBoxIcon.Information);
            });
        }

        // ----- helpers -----------------------------------------------------------

        private static void OpenPath(string path)
        {
            try { Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); }
            catch (Exception ex) { MessageBox.Show("Cannot open " + path + "\r\n" + ex.Message); }
        }

        private static void OpenLog()
        {
            string log = Path.Combine(_appDir, "logs", "cloudblocker.log");
            if (File.Exists(log)) OpenPath(log); else OpenPath(_appDir);
        }

        private static void OpenManager()
        {
            string mgr = Path.Combine(_appDir, "Manage-CloudBlocker.ps1");
            if (!File.Exists(mgr)) { MessageBox.Show("Manage-CloudBlocker.ps1 not found."); return; }
            try
            {
                Process.Start(new ProcessStartInfo("powershell.exe",
                    "-NoExit -ExecutionPolicy Bypass -File \"" + mgr + "\"") { UseShellExecute = true });
            }
            catch (Exception ex) { MessageBox.Show("Cannot open manager: " + ex.Message); }
        }

        private static int RunCmd(string file, string args, out string output)
        {
            var psi = new ProcessStartInfo(file, args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            var p = Process.Start(psi);
            output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit();
            return p.ExitCode;
        }

        private static bool StartupTaskExists()
        {
            string o;
            return RunCmd("schtasks.exe", "/Query /TN \"" + StartupTaskName + "\"", out o) == 0;
        }

        private static void ToggleStartup()
        {
            string o;
            if (StartupTaskExists())
            {
                RunCmd("schtasks.exe", "/Delete /TN \"" + StartupTaskName + "\" /F", out o);
            }
            else
            {
                string tr = "\"\\\"" + Application.ExecutablePath + "\\\"\"";
                RunCmd("schtasks.exe",
                    "/Create /SC ONLOGON /RL HIGHEST /F /TN \"" + StartupTaskName + "\" /TR " + tr, out o);
            }
            UpdateStartupCheck();
        }

        private static void UpdateStartupCheck()
        {
            if (_startupItem != null) _startupItem.Checked = StartupTaskExists();
        }
    }
}
