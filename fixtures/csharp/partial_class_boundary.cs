// F-004 fixture: the partial-class edge case. Two partial declarations of one
// type appear in one file. The narrow scan records both literally and does not
// merge them. H-007 gives each block its own disambiguated identity key, so the
// file cannot contribute a repeated node id; the expectation is recorded
// explicitly rather than guessed. Component-local.
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
