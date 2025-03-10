namespace BookTrack.Data.Entities;

public class Book
{
    public Guid Id { get; set; }
    public string Title { get; set; } = null!;
    public string Author { get; set; } = null!;
    public string? Description { get; set; }
}
