namespace AgriMap.Web.Service.Shared.Extensions;

public static class DateTimeExtensions
{
    public const double UTC7 = 7;

    public static double TimeZoneOffset { get; } = -420.0;

    public static DateTime DateTimeUtc { get; } = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    public static DateTime GetNow()
    {
        return DateTime.UtcNow.AddMinutes(TimeZoneOffset * -1.0);
    }

    public static long ToUnixTimeSeconds(DateTime dateTime)
    {
        return ((DateTimeOffset)dateTime).ToUnixTimeSeconds();
    }

    public static long ToUnixTimeMilliseconds(DateTime dateTime)
    {
        return ((DateTimeOffset)dateTime).ToUnixTimeMilliseconds();
    }

    public static long ToUnixTimeStamp(DateTime dateTime)
    {
        return (long)(dateTime - DateTimeUtc.AddMinutes(TimeZoneOffset * -1.0)).TotalMilliseconds;
    }
}