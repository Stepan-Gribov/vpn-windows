// Developer feasibility check only. Does not open a window or start a VPN.
using System;
using System.Windows.Forms;

internal static class UiCompilerCheck
{
    [STAThread]
    private static int Main()
    {
        Console.WriteLine("Windows Forms: " + typeof(Form).Assembly.FullName);
        Console.WriteLine("CLR: " + Environment.Version);
        return 0;
    }
}
