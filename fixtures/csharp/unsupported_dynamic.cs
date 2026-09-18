// F-004 fixture: constructs the C# narrow scan must NOT claim to support.
// dynamic dispatch, reflection, recursive reflection and source-generated
// members are documented unsupported cases; the scan must not fabricate a
// symbol or a call target for any of them. Component-local regression fixture.
namespace App.Unsupported
{
    public class Reflective
    {
        public void RunDynamic(dynamic target)
        {
            target.Run();
        }

        public void RunReflection(string methodName)
        {
            var type = typeof(Reflective);
            type.GetMethod(methodName);
            object instance = Activator.CreateInstance(type);
        }
    }

    public partial class GeneratedPart
    {
    }
}
