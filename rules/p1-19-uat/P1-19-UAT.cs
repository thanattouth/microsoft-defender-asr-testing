using System;
using System.Threading;

class Program
{
    static void Main()
    {
        Console.Title = "MDE P1-19 UAT";
        Console.WriteLine("MDE P1-19 Stop and Quarantine UAT");
        Console.WriteLine("This is a harmless test process.");
        Console.WriteLine("PID: " + System.Diagnostics.Process.GetCurrentProcess().Id);
        Console.WriteLine("Waiting for MDE response action...");

        while (true)
        {
            Thread.Sleep(5000);
        }
    }
}
