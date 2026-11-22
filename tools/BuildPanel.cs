using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace TnDtun.BuildTools
{
    sealed class BuildPanel : Form
    {
        readonly string root;
        readonly string smokeOutput;
        readonly Label heading = new Label();
        readonly Label status = new Label();
        readonly TextBox details = new TextBox();
        readonly TextBox log = new TextBox();
        readonly CheckBox restore = new CheckBox();
        readonly Button build = new Button();
        readonly Button result = new Button();
        readonly ProgressBar progress = new ProgressBar();
        bool building;
        string artifact;

        internal BuildPanel(string projectRoot, string smoke)
        {
            root = Path.GetFullPath(projectRoot).TrimEnd(Path.DirectorySeparatorChar);
            smokeOutput = smoke;
            Text = "TnDtun — сборка и сведения о проекте";
            Font = new Font("Segoe UI", 10);
            BackColor = Color.FromArgb(246, 248, 251);
            ForeColor = Color.FromArgb(32, 45, 61);
            AutoScaleMode = AutoScaleMode.Dpi;
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(860, 660);
            MinimumSize = new Size(720, 650);
            try { Icon = new Icon(Path.Combine(root, "resources", "TnDtun.ico")); } catch { }

            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(20), ColumnCount = 1, RowCount = 7 };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            foreach (int height in new[] { 45, 215, 35, 48, 28, 12 })
                layout.RowStyles.Add(new RowStyle(SizeType.Absolute, height));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            Controls.Add(layout);
            heading.Font = new Font("Segoe UI", 18, FontStyle.Bold);
            heading.Dock = DockStyle.Fill;
            layout.Controls.Add(heading, 0, 0);
            ConfigureText(details);
            details.Font = Font;
            layout.Controls.Add(details, 0, 1);
            restore.Text = "Загрузить зависимости из интернета (для первой сборки)";
            restore.Dock = DockStyle.Fill;
            layout.Controls.Add(restore, 0, 2);
            var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill };
            ConfigureButton(build, "Собрать ZIP");
            build.BackColor = Color.FromArgb(33, 104, 210);
            build.ForeColor = Color.White;
            build.Click += async (s, e) => await Build();
            ConfigureButton(result, "Открыть папку с ZIP");
            result.Click += (s, e) => OpenResult();
            buttons.Controls.Add(build);
            buttons.Controls.Add(result);
            layout.Controls.Add(buttons, 0, 3);
            status.Dock = DockStyle.Fill;
            status.TextAlign = ContentAlignment.MiddleLeft;
            status.Text = "Готово к сборке. Версия задаётся в project.json.";
            layout.Controls.Add(status, 0, 4);
            progress.Dock = DockStyle.Fill;
            progress.Visible = false;
            progress.Style = ProgressBarStyle.Marquee;
            layout.Controls.Add(progress, 0, 5);
            ConfigureText(log);
            log.Font = new Font("Consolas", 9);
            log.WordWrap = false;
            log.ScrollBars = ScrollBars.Both;
            layout.Controls.Add(log, 0, 6);
            RefreshDetails();
            FormClosing += (s, e) => {
                if (building) {
                    e.Cancel = true;
                    status.Text = "Дождитесь завершения сборки, затем закройте окно.";
                }
            };
            if (smokeOutput != null) Shown += async (s, e) => {
                bool ok = await Build();
                try {
                    Directory.CreateDirectory(smokeOutput);
                    using (var bitmap = new Bitmap(Width, Height)) {
                        DrawToBitmap(bitmap, new Rectangle(Point.Empty, bitmap.Size));
                        bitmap.Save(Path.Combine(smokeOutput, "build-panel.png"));
                    }
                    File.WriteAllText(Path.Combine(smokeOutput, "build-panel-result.txt"),
                        (ok ? "PASS" : "FAIL") + Environment.NewLine + details.Text + Environment.NewLine + log.Text, Encoding.UTF8);
                    Environment.ExitCode = ok ? 0 : 1;
                } catch { Environment.ExitCode = 1; }
                Close();
            };
        }

        static void ConfigureText(TextBox box)
        {
            box.Dock = DockStyle.Fill;
            box.Multiline = true;
            box.ReadOnly = true;
            box.BackColor = Color.White;
            box.ScrollBars = ScrollBars.Vertical;
            box.BorderStyle = BorderStyle.FixedSingle;
        }

        static void ConfigureButton(Button button, string text)
        {
            button.Text = text;
            button.AutoSize = true;
            button.MinimumSize = new Size(160, 36);
            button.FlatStyle = FlatStyle.Flat;
            button.BackColor = Color.White;
            button.Margin = new Padding(0, 4, 12, 4);
        }

        static Dictionary<string, object> ReadJson(string path)
        {
            return new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(File.ReadAllText(path, Encoding.UTF8));
        }

        static string Value(Dictionary<string, object> data, string key)
        {
            object value;
            return data.TryGetValue(key, out value) ? Convert.ToString(value) : "";
        }

        void RefreshDetails()
        {
            var project = ReadJson(Path.Combine(root, "project.json"));
            string version = Value(project, "version");
            heading.Text = "TnDtun · " + version;
            var text = new StringBuilder();
            text.AppendLine("Проект: " + root);
            text.AppendLine("Версия проекта: " + version + "    Версия EXE: " + Value(project, "fileVersion"));
            text.AppendLine("Платформа: Windows x64 · " + Value(project, "framework"));
            text.AppendLine();
            artifact = null;
            string last = Path.Combine(root, "dist", "last-build.json");
            if (File.Exists(last)) {
                try {
                    var info = ReadJson(last);
                    string candidate = Path.GetFullPath(Value(info, "artifact"));
                    string dist = Path.Combine(root, "dist") + Path.DirectorySeparatorChar;
                    if (candidate.StartsWith(dist, StringComparison.OrdinalIgnoreCase) && File.Exists(candidate)) artifact = candidate;
                    text.AppendLine("Последняя успешная сборка: " + Value(info, "version"));
                    text.AppendLine("Номер сборки: " + Value(info, "buildId"));
                    DateTime date;
                    text.AppendLine("Дата: " + (DateTime.TryParse(Value(info, "builtAtUtc"), out date) ? date.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss zzz") : Value(info, "builtAtUtc")));
                    text.AppendLine("Ревизия кода: " + Value(info, "sourceCommit"));
                    text.AppendLine("Незакоммиченные изменения: " + (Value(info, "sourceDirty") == "True" ? "да" : Value(info, "sourceDirty") == "False" ? "нет" : "нет сведений"));
                    text.AppendLine("Инструменты: " + Value(info, "goVersion") + " · C# " + Value(info, "csharpCompiler"));
                    text.Append("ZIP: " + (artifact == null ? "файл перемещён или удалён" : Path.GetFileName(artifact)));
                } catch (Exception e) { text.Append("Не удалось прочитать последнюю сборку: " + e.Message); }
            } else text.Append("Сборок с метаданными пока нет. Нажмите «Собрать ZIP».");
            details.Text = text.ToString();
            result.Enabled = artifact != null && !building;
        }

        void AppendLog(string line)
        {
            if (line == null || IsDisposed || !IsHandleCreated) return;
            BeginInvoke((Action)(() => { if (!IsDisposed) log.AppendText(line + Environment.NewLine); }));
        }

        async Task<bool> Build()
        {
            if (building) return false;
            building = true;
            build.Enabled = restore.Enabled = result.Enabled = false;
            progress.Visible = true;
            log.Clear();
            status.Text = restore.Checked ? "Загрузка зависимостей и сборка…" : "Сборка приложения и ZIP…";
            bool ok = false;
            try {
                var info = new ProcessStartInfo("powershell.exe",
                    "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + Path.Combine(root, "Build-Windows.ps1") + "\"" + (restore.Checked ? " -RestoreDependencies" : "")) {
                    WorkingDirectory = root, UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
                };
                // An already-open editor can still have PATH from before tool installation.
                foreach (string extra in new[] { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Go", "bin"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Git", "cmd") })
                    if (Directory.Exists(extra)) info.EnvironmentVariables["PATH"] += ";" + extra;
                using (var process = new Process { StartInfo = info }) {
                    process.OutputDataReceived += (s, e) => AppendLog(e.Data);
                    process.ErrorDataReceived += (s, e) => AppendLog(e.Data);
                    process.Start();
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();
                    await Task.Run(() => process.WaitForExit());
                    ok = process.ExitCode == 0;
                    status.Text = ok ? "Готово. ZIP можно открыть и передать другим людям." : "Сборка не завершилась. Причина указана в журнале ниже.";
                }
            } catch (Exception e) {
                log.AppendText(e.Message + Environment.NewLine);
                status.Text = "Не удалось запустить сборку. Смотрите журнал ниже.";
            } finally {
                building = false;
                build.Enabled = restore.Enabled = true;
                progress.Visible = false;
                RefreshDetails();
            }
            return ok;
        }

        void OpenResult()
        {
            if (artifact == null) return;
            try { Process.Start("explorer.exe", "/select,\"" + artifact + "\""); }
            catch (Exception e) { MessageBox.Show(this, e.Message, "TnDtun"); }
        }

        [STAThread]
        static int Main(string[] args)
        {
            try {
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                string smoke = args.Length == 3 && args[1] == "--smoke" ? args[2] : null;
                using (var panel = new BuildPanel(args[0], smoke)) Application.Run(panel);
                return Environment.ExitCode;
            } catch (Exception e) {
                if (args.Length == 3 && args[1] == "--smoke") {
                    Directory.CreateDirectory(args[2]);
                    File.WriteAllText(Path.Combine(args[2], "build-panel-result.txt"), "FAIL: " + e, Encoding.UTF8);
                } else MessageBox.Show(e.Message, "TnDtun — сборка");
                return 1;
            }
        }
    }
}
