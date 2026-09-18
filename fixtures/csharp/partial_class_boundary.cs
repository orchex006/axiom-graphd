// F-004 fixture: the partial-class edge case. Two partial declarations of one
// type appear in one file. The narrow scan records both literally and does not
// merge them, so the two class declarations can share one identity key. The
// expectation is recorded explicitly rather than guessed. Component-local.
namespace App.Partial
{
    public partial class Widget
    {
        public void First()
        {
        }
    }

    public partial class Widget
    {
        public void Second()
        {
        }
    }
}
