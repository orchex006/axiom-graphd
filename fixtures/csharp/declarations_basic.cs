// F-004 fixture: minimal C# declarations the B-048 narrow scan must extract.
// Supported evidence kinds: declarations (namespace, interface, class, struct,
// record, enum, method) and literal inheritance headers. This file is a
// component-local regression fixture of axiom-graphd; it is not a shared
// contract fixture and is not registered in axiom-specs conformance.
using System;
using System.Threading.Tasks;

namespace App.Core
{
    public interface IClock
    {
        DateTime Now();
    }

    public class SystemClock : IClock
    {
        public DateTime Now()
        {
            return DateTime.MinValue;
        }
    }

    public abstract class HandlerBase
    {
        public abstract Task HandleAsync(string name);
    }

    public sealed class GreetingHandler : HandlerBase, IClock
    {
        public GreetingHandler(IClock clock)
        {
        }

        public DateTime Now()
        {
            return DateTime.MinValue;
        }

        public Task HandleAsync(string name)
        {
            return Task.CompletedTask;
        }
    }

    public readonly struct Point
    {
        public int X { get; }
    }

    public record Greeting(string Name);

    public enum Color
    {
        Red,
        Green
    }
}
