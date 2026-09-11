using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

public class Loader
{
    public object Load(Stream stream)
    {
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(stream);
    }
}
