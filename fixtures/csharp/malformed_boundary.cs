// F-004 fixture: malformed input must be reported, never silently empty.
// The nameless class keyword and the unbalanced braces are diagnostics, and
// coverage must not claim completeness for this file. Component-local.
namespace App.Broken
{
    public class
    {
        public void Run()
        {
    }
}
